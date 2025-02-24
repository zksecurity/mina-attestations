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
  Field,
} from 'o1js';
import { ProvableType } from './o1js-missing.ts';
import {
  inferNestedProvable,
  type InferNestedProvable,
  NestedProvable,
  type NestedProvableFor,
} from './nested.ts';
import { prefixes } from './constants.ts';
import {
  type CredentialSpec,
  type Credential,
  type StoredCredential,
  hashCredential,
  withOwner,
  type WitnessSpec,
} from './credential.ts';
import { assert } from './util.ts';
import {
  deserializeProvableType,
  replaceNull,
  replaceUndefined,
  serializeProvableType,
} from './serialize-provable.ts';
import type { ImportedWitnessSpecJSON } from './validation.ts';

export { Imported, type ImportedWitness, ImportedWitnessSpec };

type ImportedWitness<Input = unknown> = {
  type: 'imported';
  vk: VerificationKey;
  proof: DynamicProof<Input, Credential>;
};

type ImportedWitnessSpec = {
  type: 'imported';
  publicInputType: ProvableType;
  publicOutputType: ProvableType<Credential<any>>;
  maxProofsVerified: 0 | 1 | 2;
  featureFlags: FeatureFlags;
};

type Imported<Data, Input> = StoredCredential<Data, ImportedWitness<Input>>;

const Imported = {
  create: createImported,
  fromProgram: importedFromProgram,
  fromMethod: importedFromMethod,

  publicInputType,

  Generic: {
    witnessType<Input>(
      witnessSpec: WitnessSpec
    ): NestedProvableFor<ImportedWitness<Input>> {
      assert(witnessSpec?.type === 'imported');
      let {
        publicInputType,
        publicOutputType,
        maxProofsVerified,
        featureFlags,
      } = witnessSpec;

      class Proof extends DynamicProof<unknown, Credential> {
        static publicInputType = ProvableType.get(publicInputType);
        static publicOutputType = ProvableType.get(publicOutputType);
        static maxProofsVerified = maxProofsVerified;
        static featureFlags = featureFlags;
      }
      return {
        type: ProvableType.constant('imported'),
        vk: VerificationKey,
        proof: Proof,
      };
    },

    // verify the proof, check that its public output is exactly the credential
    verify({ vk, proof }: ImportedWitness, credHash: Field): void {
      proof.verify(vk);
      hashCredential(proof.publicOutput).assertEquals(
        credHash,
        'Invalid proof output'
      );
    },

    async validate({ vk, proof }: ImportedWitness, credHash: Field) {
      let ok = await verify(proof, vk);
      assert(ok, 'Invalid proof');
      hashCredential(proof.publicOutput).assertEquals(
        credHash,
        'Invalid proof output'
      );
    },

    matchesSpec(witness: ImportedWitness) {
      // TODO should check proof type
      return witness.type === 'imported';
    },
  },
};

function createImported<
  DataType extends NestedProvable,
  InputType extends ProvableType,
  Data extends InferNestedProvable<DataType>,
  Input extends InferProvable<InputType>
>(spec: {
  data: DataType;
  witness: ImportedWitnessSpec;
}): CredentialSpec<ImportedWitness<Input>, Data> {
  return {
    credentialType: 'imported',
    data: NestedProvable.get(inferNestedProvable(spec.data)),
    witness: spec.witness,

    witnessType: Imported.Generic.witnessType,
    verify: Imported.Generic.verify,
    validate: Imported.Generic.validate,
    matchesSpec: Imported.Generic.matchesSpec,

    // issuer == hash of vk and public input
    issuer({ vk, proof }) {
      let credIdent = Poseidon.hash(
        ProvableType.get(spec.witness.publicInputType).toFields(
          proof.publicInput
        )
      );
      return Poseidon.hashWithPrefix(prefixes.issuerImported, [
        vk.hash,
        credIdent,
      ]);
    },
  };
}

function witnessSpecToJSON(spec: ImportedWitnessSpec) {
  return {
    type: spec.type,
    publicInputType: serializeProvableType(spec.publicInputType),
    publicOutputType: serializeProvableType(spec.publicOutputType),
    maxProofsVerified: spec.maxProofsVerified,
    featureFlags: replaceUndefined(spec.featureFlags),
  };
}

function witnessSpecFromJSON(
  json: ImportedWitnessSpecJSON
): ImportedWitnessSpec {
  return {
    type: json.type,
    publicInputType: deserializeProvableType(json.publicInputType),
    publicOutputType: deserializeProvableType(json.publicOutputType),
    maxProofsVerified: json.maxProofsVerified,
    featureFlags: replaceNull(json.featureFlags),
  };
}

const ImportedWitnessSpec = {
  toJSON: witnessSpecToJSON,
  fromJSON: witnessSpecFromJSON,
};

function publicInputType<Spec extends CredentialSpec>(
  credentialSpec: Spec
): ProvableType {
  assert(credentialSpec.witness?.type === 'imported');
  return credentialSpec.witness.publicInputType;
}

async function importedFromProgram<
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
    spec: createImported<Provable<Data>, InputType, Data, Input>({
      data: dataType,
      witness: {
        type: 'imported',
        publicInputType: program.publicInputType,
        publicOutputType: program.publicOutputType,
        maxProofsVerified,
        featureFlags,
      },
    }),

    program,

    async create(...inputs: AllInputs) {
      let vk = await self.compile();
      let { proof } = await program.run(...inputs);
      return self.fromProof(proof, vk);
    },

    async fromProof(
      proof: Proof<Input, Credential<Data>>,
      vk: VerificationKey
    ): Promise<Imported<Data, Input>> {
      let dynProof = InputProof.fromProof(proof);
      return {
        version: 'v0',
        metadata: undefined,
        credential: proof.publicOutput,
        witness: { type: 'imported', vk, proof: dynProof },
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
    }: Credential<From<DataType>>): Promise<Imported<Data, Input>> {
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
        witness: { type: 'imported', vk, proof: dummyProof },
      };
    },
  };

  return self;
}

type PublicInput<Config> = InferProvableOrUndefined<Get<Config, 'publicInput'>>;
type PrivateInput<Config> = InferProvable<Get<Config, 'privateInput'>>;
type Data<Config> = InferProvable<Get<Config, 'data'>>;

// TODO type returned from this should be annotated
async function importedFromMethod<
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

  let credentialSpec = await importedFromProgram<
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
