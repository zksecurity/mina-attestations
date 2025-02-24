import {
  PublicKey,
  Signature,
  Undefined,
  Field,
  PrivateKey,
  Group,
  Poseidon,
} from 'o1js';
import {
  inferNestedProvable,
  type InferNestedProvable,
  NestedProvable,
  type NestedProvableFor,
} from './nested.ts';
import { zip } from './util.ts';
import { hashDynamic, provableTypeMatches } from './dynamic/dynamic-hash.ts';
import type { JSONValue } from './types.ts';
import type { ImportedWitnessSpec } from './credential-imported.ts';

export {
  type Credential,
  type CredentialSpec,
  type WitnessSpec,
  type CredentialType,
  type CredentialInputs,
  type CredentialOutputs,
  hashCredential,
  verifyCredentials,
  signCredentials,
  type StoredCredential,
  withOwner,
  Unsigned,
  unsafeMissingOwner,
  createUnsigned,
  credentialMatchesSpec,
};

/**
 * A credential is a generic piece of data (the "attributes") along with an owner represented by a public key.
 */
type Credential<Data = unknown> = { owner: PublicKey; data: Data };

/**
 * The different types of credential we currently support.
 */
type CredentialType = 'unsigned' | 'native' | 'imported';

/**
 * A credential spec is:
 * - a string `credentialType` identifying the credential type
 * - a "witness" type for private parameters
 * - a type for data (which is left generic when defining credential types)
 * - a function `verify(...)` that verifies the credential inside a ZkProgram circuit
 * - a function `validate(...)` that verifies the credential in normal JS
 * - a function `issuer(...)` that derives a commitment to the "issuer" of the credential, e.g. a public key for signed credentials
 * - a function `matchesSpec(...)` that decides whether a stored credential's witness matches the spec
 */
type CredentialSpec<Witness = unknown, Data = unknown> = {
  credentialType: CredentialType;
  data: NestedProvableFor<Data>;
  witness: WitnessSpec;

  witnessType(type: WitnessSpec): NestedProvableFor<Witness>;

  verify(witness: Witness, credHash: Field): void;
  issuer(witness: Witness): Field;
  validate(witness: Witness, credHash: Field): Promise<void>;

  matchesSpec(witness: Witness): boolean;
};

type WitnessSpec = ImportedWitnessSpec | undefined;

/**
 * Credential in stored form, including the witness and metadata.
 */
type StoredCredential<Data = unknown, Witness = unknown> = {
  version: 'v0';
  witness: Witness;
  metadata: JSONValue | undefined;
  credential: Credential<Data>;
};

/**
 * Hash a credential.
 */
function hashCredential({ owner, data }: Credential) {
  let ownerHash = Poseidon.hash(owner.toFields());
  let dataHash = hashDynamic(data);
  return Poseidon.hash([ownerHash, dataHash]);
}

/**
 * Inputs to verify credentials inside a presentation proof.
 */
type CredentialInputs = {
  context: Field;
  ownerSignature: Signature;

  credentials: {
    spec: CredentialSpec;
    credential: Credential;
    witness: unknown;
  }[];
};

/**
 * Outputs of verifying credentials, used as inputs to application circuit.
 */
type CredentialOutputs = {
  owner: PublicKey;
  credentials: {
    data: unknown;
    witness: unknown;
    issuer: Field;
  }[];
};

function verifyCredentials({
  context,
  ownerSignature,
  credentials,
}: CredentialInputs): CredentialOutputs {
  // pack credentials in hashes
  let credHashes = credentials.map(({ credential }) =>
    hashCredential(credential)
  );

  // verify each credential using its own verification method
  zip(credentials, credHashes).forEach(([{ spec, witness }, credHash]) => {
    spec.verify(witness, credHash);
  });

  // create issuer hashes for each credential
  let issuers = credentials.map(({ spec, witness }) => spec.issuer(witness));

  // assert that all credentials have the same owner, and determine that owner
  let owner: undefined | PublicKey;

  credentials.forEach(({ credential }) => {
    owner ??= credential.owner; // set to the first owner
    credential.owner.assertEquals(owner);
  });

  // verify the owner signature
  if (owner !== undefined) {
    let ok = ownerSignature.verify(owner, [
      context,
      ...zip(credHashes, issuers).flat(),
    ]);
    ok.assertTrue('Invalid owner signature');
  }

  return {
    owner: owner ?? PublicKey.empty(), // use a (0,0) public key in case there are no credentials

    // credential-issuer pairs
    credentials: zip(credentials, issuers).map(
      ([{ credential, witness }, issuer]) => ({
        data: credential.data,
        witness,
        issuer,
      })
    ),
  };
}

function signCredentials<Private, Data>(
  ownerKey: PrivateKey,
  context: Field,
  ...credentials: {
    credentialType: CredentialSpec<Private, Data>;
    credential: Credential<Data>;
    witness: Private;
  }[]
) {
  let hashes = credentials.map(({ credential }) => hashCredential(credential));
  let issuers = credentials.map(({ credentialType, witness }) =>
    credentialType.issuer(witness)
  );
  return Signature.create(ownerKey, [context, ...zip(hashes, issuers).flat()]);
}

function credentialMatchesSpec(
  spec: CredentialSpec,
  credential: StoredCredential
): boolean {
  // check version
  if (credential.version !== 'v0') return false;

  // credential-specific check
  if (!spec.matchesSpec(credential.witness)) return false;

  // check that the data type matches
  return provableTypeMatches(credential.credential.data, spec.data);
}

// dummy credential with no proof attached

type Unsigned<Data> = StoredCredential<Data, undefined>;

const UnsignedBase = {
  credentialType: 'unsigned' as const,
  witness: undefined,

  witnessType() {
    return Undefined;
  },

  // do nothing
  verify() {},
  async validate() {},

  // dummy issuer
  issuer() {
    return Field(0);
  },

  // always matches
  matchesSpec() {
    return true;
  },
};

function Unsigned<DataType extends NestedProvable>(
  data: DataType
): CredentialSpec<undefined, InferNestedProvable<DataType>> {
  return { ...UnsignedBase, data: inferNestedProvable(data) };
}

function unsafeMissingOwner(): PublicKey {
  return PublicKey.fromGroup(Group.generator);
}

function createUnsigned<Data>(
  data: Data,
  metadata?: JSONValue
): Unsigned<Data> {
  return {
    version: 'v0',
    metadata,
    credential: { owner: unsafeMissingOwner(), data },
    witness: undefined,
  };
}

// helpers to create derived types

function withOwner<DataType extends NestedProvable>(data: DataType) {
  return { owner: PublicKey, data };
}
