import {
  assert,
  Provable,
  PublicKey,
  Signature,
  Undefined,
  VerificationKey,
  type ProvablePure,
  DynamicProof,
  type InferProvable,
  FeatureFlags,
  Proof,
  Field,
  type ProvableHashable,
  Hashed,
  Poseidon,
  PrivateKey,
} from 'o1js';
import {
  assertPure,
  ProvableType,
  type ProvablePureType,
} from './o1js-missing.ts';
import {
  type InferNestedProvable,
  NestedProvable,
  type NestedProvableFor,
  type NestedProvablePure,
  type NestedProvablePureFor,
} from './nested.ts';
import { zip } from './util.ts';

export {
  Credential,
  type CredentialType,
  type CredentialId,
  type CredentialInputs,
  type CredentialOutputs,
  verifyCredentials,
  signCredential,
};

export { HashedCredential };

/**
 * A credential is a generic piece of data (the "attributes") along with an owner represented by a public key.
 */
type Credential<Data> = { owner: PublicKey; data: Data };

/**
 * The different types of credential we currently support.
 */
type CredentialId = 'none' | 'signature-native' | 'proof';

/**
 * A credential type is:
 * - a string id fully identifying the credential type
 * - a type for private parameters
 * - a type for data (which is left generic when defining credential types)
 * - a function `verify(...)` that asserts the credential is valid
 * - a function `issuer(...)` that derives a commitment to the "issuer" of the credential, e.g. a public key for signed credentials
 */
type CredentialType<
  Id extends CredentialId = CredentialId,
  Private = any,
  Data = any
> = {
  type: 'credential';
  id: Id;
  private: NestedProvableFor<Private>;
  data: NestedProvablePureFor<Data>;

  verify(privateInput: Private, credHash: Hashed<Credential<Data>>): void;

  issuer(privateInput: Private): Field;
};

/**
 * Inputs to verify credentials inside a presentation proof.
 */
type CredentialInputs = {
  context: Field;
  ownerSignature: Signature;

  credentials: {
    credentialType: CredentialType;
    credential: Credential<any>;
    privateInput: any;
  }[];
};

/**
 * Outputs of verifying credentials, used as inputs to application circuit.
 */
type CredentialOutputs = {
  owner: PublicKey;
  credentials: {
    credential: Credential<any>;
    issuer: Field;
  }[];
};

function verifyCredentials({
  context,
  ownerSignature,
  credentials,
}: CredentialInputs): CredentialOutputs {
  // pack credentials in hashes
  let credHashes = credentials.map(({ credentialType: { data }, credential }) =>
    HashedCredential(data).hash(credential)
  );

  // verify each credential using its own verification method
  zip(credentials, credHashes).forEach(
    ([{ credentialType, privateInput }, credHash]) => {
      credentialType.verify(privateInput, credHash);
    }
  );

  // TODO would be nice to make this a `Hashed<Issuer>` over a more informative `Issuer` type, for easier use in the app circuit
  let issuers = credentials.map(({ credentialType, privateInput }) =>
    credentialType.issuer(privateInput)
  );

  // assert that all credentials have the same owner, and determine that owner
  let owner: undefined | PublicKey;

  credentials.forEach(({ credential }) => {
    owner ??= credential.owner; // set to the first owner
    credential.owner.assertEquals(owner);
  });

  // verify the owner signature
  if (owner !== undefined) {
    let hashes = credHashes.map((c) => c.hash);
    let ok = ownerSignature.verify(owner, [
      context,
      ...zip(hashes, issuers).flat(),
    ]);
    ok.assertTrue('Invalid owner signature');
  }

  return {
    owner: owner ?? PublicKey.empty(), // use a (0,0) public key in case there are no credentials

    // credential-issuer pairs
    credentials: zip(credentials, issuers).map(([{ credential }, issuer]) => ({
      credential,
      issuer,
    })),
  };
}

// TODO support many credentials
function signCredential<Private, Data>(
  ownerKey: PrivateKey,
  inputs: {
    credentialType: CredentialType<any, Private, Data>;
    context: Field;
    credential: Credential<Data>;
    privateInput: Private;
  }
) {
  let { credentialType, context, credential, privateInput } = inputs;
  let credHash = HashedCredential(credentialType.data).hash(credential);
  let issuer = credentialType.issuer(privateInput);
  return Signature.create(ownerKey, [context, credHash.hash, issuer]);
}

function defineCredential<
  Id extends CredentialId,
  PrivateType extends NestedProvable
>(config: {
  id: Id;
  private: PrivateType;

  verify<Data>(
    privateInput: InferNestedProvable<PrivateType>,
    credHash: Hashed<Credential<Data>>
  ): void;

  issuer(privateInput: InferNestedProvable<PrivateType>): Field;
}) {
  return function credential<DataType extends NestedProvablePure>(
    dataType: DataType
  ): CredentialType<
    Id,
    InferNestedProvable<PrivateType>,
    InferNestedProvable<DataType>
  > {
    return {
      type: 'credential',
      id: config.id,
      private: config.private as any,
      data: dataType as any,
      verify: config.verify,
      issuer: config.issuer,
    };
  };
}

// dummy credential with no proof attached
const None = defineCredential({
  id: 'none',
  private: Undefined,

  // do nothing
  verify() {},

  // dummy issuer
  issuer() {
    return Field(0);
  },
});

// native signature
const Signed = defineCredential({
  id: 'signature-native',
  private: {
    issuerPublicKey: PublicKey,
    issuerSignature: Signature,
  },

  // verify the signature
  verify({ issuerPublicKey, issuerSignature }, credHash) {
    let ok = issuerSignature.verify(issuerPublicKey, [credHash.hash]);
    assert(ok, 'Invalid signature');
  },

  // issuer == issuer public key
  issuer({ issuerPublicKey }) {
    return Poseidon.hashWithPrefix(
      'mina-cred:v0:simple',
      issuerPublicKey.toFields()
    );
  },
});

function Proved<
  DataType extends NestedProvablePure,
  InputType extends ProvablePureType,
  Data extends InferNestedProvable<DataType>,
  Input extends InferProvable<InputType>
>(
  Proof: typeof DynamicProof<Input, Credential<Data>>,
  dataType: DataType
): CredentialType<
  'proof',
  {
    vk: VerificationKey;
    proof: DynamicProof<Input, Credential<Data>>;
  },
  Data
> {
  // TODO annoying that this cast doesn't work without overriding the type
  let data: NestedProvablePureFor<Data> = dataType as any;
  const credentialType = HashableCredential(data);
  return {
    type: 'credential',
    id: 'proof',
    private: { vk: VerificationKey, proof: Proof },
    data: NestedProvable.get(data),

    // verify the proof, check that its public output is exactly the credential
    verify({ vk, proof }, credHash) {
      proof.verify(vk);
      let credential = credHash.unhash();
      Provable.assertEqual(credentialType, proof.publicOutput, credential);
    },

    // issuer == hash of vk and public input
    issuer({ vk, proof }) {
      let credIdent = Poseidon.hash(
        Proof.publicInputType.toFields(proof.publicInput)
      );
      return Poseidon.hashWithPrefix('mina-cred:v0:recursive', [
        vk.hash,
        credIdent,
      ]);
    },
  };
}

async function ProvedFromProgram<
  DataType extends ProvablePure<any>,
  InputType extends ProvablePure<any>,
  Data extends InferNestedProvable<DataType>,
  Input extends InferProvable<InputType>
>(
  {
    program,
  }: {
    program: {
      publicInputType: InputType;
      publicOutputType: ProvablePure<Credential<Data>>;
      analyzeMethods: () => Promise<{
        [I in keyof any]: any;
      }>;
    };
  },
  // TODO this needs to be exposed on the program!!
  maxProofsVerified: 0 | 1 | 2 = 0
) {
  const featureFlags = await FeatureFlags.fromZkProgram(program);

  class InputProof extends DynamicProof<Input, Credential<Data>> {
    static publicInputType = program.publicInputType;
    static publicOutputType = program.publicOutputType;
    static maxProofsVerified = maxProofsVerified;
    static featureFlags = featureFlags;
  }

  let data = ProvableType.synthesize(program.publicOutputType).data;
  let dataType = NestedProvable.get(NestedProvable.fromValue(data));
  assertPure(dataType);

  return Object.assign(
    Proved<ProvablePure<Data>, InputType, Data, Input>(InputProof, dataType),
    {
      fromProof(
        proof: Proof<Input, Credential<Data>>
      ): DynamicProof<Input, Credential<Data>> {
        return InputProof.fromProof(proof as any);
      },
      dummyProof(
        publicInput: Input,
        publicOutput: Credential<Data>
      ): Promise<DynamicProof<Input, Credential<Data>>> {
        return InputProof.dummy(
          publicInput,
          publicOutput as any,
          maxProofsVerified
        );
      },
    }
  );
}

const Credential = {
  none: None,
  proof: Proved,
  proofFromProgram: ProvedFromProgram,
  signatureNative: Signed,

  // type layout of a credential
  withOwner<DataType extends NestedProvable>(data: DataType) {
    return { owner: PublicKey, data };
  },
};

// helpers to create derived types

function HashableCredential<Data>(
  dataType: NestedProvableFor<Data>
): ProvableHashable<Credential<Data>> {
  return NestedProvable.get(Credential.withOwner(dataType)) as any;
}

function HashedCredential<Data>(
  dataType: NestedProvableFor<Data>
): typeof Hashed<Credential<Data>> {
  return Hashed.create(HashableCredential(dataType));
}
