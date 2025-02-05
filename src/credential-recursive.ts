import {
  VerificationKey,
  DynamicProof,
  type InferProvable,
  FeatureFlags,
  Proof,
  Poseidon,
  verify,
  Cache,
  ZkProgram,
  Provable,
  PublicKey,
  Undefined,
  type From,
  type InferValue,
} from 'o1js';
import { ProvableType } from './o1js-missing.ts';
import {
  type InferNestedProvable,
  NestedProvable,
  type NestedProvableFor,
} from './nested.ts';
import { prefixes } from './constants.ts';
import {
  type CredentialSpec,
  type Credential,
  type StoredCredential,
  defineCredential,
  credentialHash,
  hashCredentialInCircuit,
  withOwner,
} from './credential.ts';
import { assert, assertHasProperty } from './util.ts';

export { Recursive, type Witness };

type Witness<Data = any, Input = any> = {
  type: 'recursive';
  vk: VerificationKey;
  proof: DynamicProof<Input, Credential<Data>>;
};

type Recursive<Data, Input> = StoredCredential<
  Data,
  Witness<Data, Input>,
  undefined
>;

function Recursive<
  DataType extends NestedProvable,
  InputType extends ProvableType,
  Data extends InferNestedProvable<DataType>,
  Input extends InferProvable<InputType>
>(
  Proof: typeof DynamicProof<Input, Credential<Data>>,
  dataType: DataType
): CredentialSpec<'recursive', Witness<Data, Input>, Data> {
  // TODO annoying that this cast doesn't work without overriding the type
  const data: NestedProvableFor<Data> = dataType as any;

  return {
    type: 'credential',
    credentialType: 'recursive',
    witness: {
      type: ProvableType.constant('recursive'),
      vk: VerificationKey,
      proof: Proof,
    },
    data: NestedProvable.get(data),

    // verify the proof, check that its public output is exactly the credential
    verify({ vk, proof }, credHash) {
      proof.verify(vk);
      hashCredentialInCircuit(data, proof.publicOutput).hash.assertEquals(
        credHash.hash,
        'Invalid proof output'
      );
    },
    async verifyOutsideCircuit({ vk, proof }, credHash) {
      let ok = await verify(proof, vk);
      assert(ok, 'Invalid proof');
      hashCredentialInCircuit(data, proof.publicOutput).hash.assertEquals(
        credHash.hash,
        'Invalid proof output'
      );
    },

    // issuer == hash of vk and public input
    issuer({ vk, proof }) {
      let credIdent = Poseidon.hash(
        Proof.publicInputType.toFields(proof.publicInput)
      );
      return Poseidon.hashWithPrefix(prefixes.issuerRecursive, [
        vk.hash,
        credIdent,
      ]);
    },
  };
}

Recursive.publicInputType = function publicInputType<
  Spec extends CredentialSpec
>(
  credentialSpec: Spec
): Spec extends CredentialSpec<'recursive', Witness<any, infer Input>>
  ? ProvableType<Input>
  : never {
  assert(credentialSpec.credentialType === 'recursive');
  assertHasProperty(credentialSpec.witness, 'proof');
  let witness = credentialSpec.witness as {
    type: Provable<'recursive'>;
    vk: typeof VerificationKey;
    proof: typeof DynamicProof;
  };
  return witness.proof.publicInputType as any;
};

const genericRecursive = defineCredential({
  credentialType: 'recursive',
  witness: {
    type: ProvableType.constant('recursive'),
    vk: VerificationKey,
    proof: DynamicProof,
  },

  // verify the proof, check that its public output is exactly the credential
  verify({ vk, proof }, credHash) {
    proof.verify(vk);
    credentialHash(proof.publicOutput).assertEquals(
      credHash.hash,
      'Invalid proof output'
    );
  },
  async verifyOutsideCircuit({ vk, proof }, credHash) {
    let ok = await verify(proof, vk);
    assert(ok, 'Invalid proof');
    credentialHash(proof.publicOutput).assertEquals(
      credHash.hash,
      'Invalid proof output'
    );
  },

  // issuer == hash of vk and public input
  issuer({ vk, proof }) {
    let credIdent = Poseidon.hash(
      (proof.constructor as typeof DynamicProof).publicInputType.toFields(
        proof.publicInput
      )
    );
    return Poseidon.hashWithPrefix(prefixes.issuerRecursive, [
      vk.hash,
      credIdent,
    ]);
  },
});

Recursive.Generic = genericRecursive;

Recursive.fromProgram = recursiveFromProgram;
Recursive.fromMethod = recursiveFromMethod;

async function recursiveFromProgram<
  DataType extends ProvableType,
  InputType extends ProvableType,
  Data extends InferProvable<DataType>,
  Input extends InferProvable<InputType>,
  AllInputs extends any[]
>(program: {
  publicInputType: InputType;
  publicOutputType: ProvableType<Credential<Data>>;
  analyzeMethods(): Promise<Record<string, any>>;
  maxProofsVerified(): Promise<0 | 1 | 2>;
  compile: (options?: {
    cache?: Cache;
    forceRecompile?: boolean;
    proofsEnabled?: boolean;
  }) => Promise<{ verificationKey: VerificationKey }>;

  run(...inputs: AllInputs): Promise<{
    proof: Proof<Input, Credential<Data>>;
    auxiliaryOutput: undefined;
  }>;
}) {
  const featureFlags = await FeatureFlags.fromZkProgram(program);
  const maxProofsVerified = await program.maxProofsVerified();

  class InputProof extends DynamicProof<Input, Credential<Data>> {
    static publicInputType: Provable<Input> = ProvableType.get(
      program.publicInputType
    );
    static publicOutputType = ProvableType.get(program.publicOutputType);
    static maxProofsVerified = maxProofsVerified;
    static featureFlags = featureFlags;
  }

  let data = ProvableType.synthesize(program.publicOutputType).data;
  let dataType = NestedProvable.get(NestedProvable.fromValue(data));

  let isCompiled = false;
  let vk: VerificationKey | undefined;

  let self = {
    spec: Recursive<Provable<Data>, InputType, Data, Input>(
      InputProof,
      dataType
    ),

    program,

    async create(...inputs: AllInputs) {
      let vk = await self.compile();
      let { proof } = await program.run(...inputs);
      return self.fromProof(proof, vk);
    },

    async fromProof(
      proof: Proof<Input, Credential<Data>>,
      vk: VerificationKey
    ): Promise<Recursive<Data, Input>> {
      let dynProof = InputProof.fromProof(proof);
      return {
        version: 'v0',
        metadata: undefined,
        credential: proof.publicOutput,
        witness: { type: 'recursive', vk, proof: dynProof },
      };
    },

    async compile(options?: {
      cache?: Cache;
      forceRecompile?: boolean;
      proofsEnabled?: boolean;
    }) {
      if (isCompiled) return vk!;
      let result = await program.compile(options);
      vk = result.verificationKey;
      isCompiled = true;
      return vk;
    },

    async dummy({
      owner,
      data,
    }: Credential<From<DataType>>): Promise<Recursive<Data, Input>> {
      let input = ProvableType.synthesize(program.publicInputType);
      let vk = await self.compile();
      let credential = { owner, data: dataType.fromValue(data) };

      let dummyProof = await InputProof.dummy(
        input,
        credential,
        maxProofsVerified
      );
      return {
        version: 'v0',
        metadata: undefined,
        credential,
        witness: { type: 'recursive', vk, proof: dummyProof },
      };
    },
  };

  return self;
}

type PublicInput<Config> = InferProvableOrUndefined<Get<Config, 'publicInput'>>;
type PrivateInput<Config> = InferProvable<Get<Config, 'privateInput'>>;
type Data<Config> = InferProvable<Get<Config, 'data'>>;

// TODO type returned from this should be annotated
async function recursiveFromMethod<
  Config extends {
    name: string;
    publicInput?: NestedProvable;
    privateInput?: NestedProvable;
    data: NestedProvable;
  }
>(
  spec: Config,
  method: (inputs: {
    publicInput: PublicInput<Config>;
    privateInput: PrivateInput<Config>;
    owner: PublicKey;
  }) => Promise<Data<Config>>
) {
  type PublicInputType = Get<Config, 'publicInput'>;
  type PublicInput = InferProvableOrUndefined<PublicInputType>;
  type PrivateInputType = Get<Config, 'privateInput'>;
  type PrivateInput = InferProvable<PrivateInputType>;
  type DataType = Get<Config, 'data'>;
  type Data = InferProvable<Get<Config, 'data'>>;

  let publicInput =
    spec.publicInput === undefined
      ? undefined
      : NestedProvable.get<PublicInput>(
          spec.publicInput as NestedProvableFor<PublicInput>
        );
  let privateInput =
    spec.privateInput === undefined
      ? Undefined
      : NestedProvable.get<PrivateInput>(
          spec.privateInput as NestedProvableFor<PrivateInput>
        );
  let publicOutput = NestedProvable.get(withOwner(spec.data));

  async function wrappedMethod(
    pub: PublicInput,
    priv: PrivateInput,
    owner: PublicKey
  ): Promise<{ publicOutput: Credential<Data> }> {
    let data = await method({ publicInput: pub, privateInput: priv, owner });
    return { publicOutput: { owner, data } };
  }

  let program = ZkProgram({
    name: spec.name,
    publicInput,
    publicOutput,
    methods: {
      run: {
        privateInputs: [privateInput, PublicKey],
        method:
          publicInput === undefined
            ? (privateInput: PrivateInput, owner: PublicKey) =>
                wrappedMethod(undefined as any, privateInput, owner)
            : wrappedMethod,
      } as any, // ZkProgram's generics are too stupid
    },
  });

  let credentialSpec = await recursiveFromProgram<
    Provable<Data, InferValue<DataType>>,
    Provable<PublicInput, InferValue<PublicInputType>>,
    Data,
    PublicInput,
    any
  >(program as any);
  return {
    ...(credentialSpec as Omit<typeof credentialSpec, 'create'>),

    async create(inputs: {
      publicInput: From<PublicInputType>;
      privateInput: From<PrivateInputType>;
      owner: PublicKey;
    }) {
      let vk = await this.compile();
      let proof: Proof<PublicInput, Credential<Data>>;
      if (publicInput === undefined) {
        ({ proof } = await (program.run as any)(
          privateInput.fromValue(inputs.privateInput),
          inputs.owner
        ));
      } else {
        ({ proof } = await (program.run as any)(
          publicInput.fromValue(inputs.publicInput),
          privateInput.fromValue(inputs.privateInput),
          inputs.owner
        ));
      }
      return credentialSpec.fromProof(proof, vk);
    },
  };
}

type Get<T, Key extends string> = T extends {
  [K in Key]: infer Value;
}
  ? Value
  : undefined;

type InferProvableOrUndefined<A> = A extends undefined
  ? undefined
  : InferProvable<A>;
