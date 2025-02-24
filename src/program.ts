import {
  Bytes,
  Field,
  Hash,
  Proof,
  ProvableType,
  Signature,
  VerificationKey,
  ZkProgram,
} from 'o1js';
import {
  type Input,
  privateInputTypes,
  publicInputTypes,
  publicOutputType,
  rootValue,
  Spec,
  splitUserInputs,
  extractCredentialInputs,
  type PublicInputs,
  type UserInputs,
  type PrivateInputs,
} from './program-spec.ts';
import { Node } from './operation.ts';
import { NestedProvable } from './nested.ts';
import { verifyCredentials } from './credential.ts';
import { serializeSpec } from './serialize-spec.ts';

export { createProgram, type Program };

type Program<Output, Inputs extends Record<string, Input>> = {
  compile(): Promise<VerificationKey>;

  run(input: UserInputs<Inputs>): Promise<Proof<PublicInputs<Inputs>, Output>>;

  program: ZkProgram<{
    publicInput: ProvableType<PublicInputs<Inputs>>;
    publicOutput: ProvableType<Output>;
    methods: {
      run: {
        privateInputs: [ProvableType<PrivateInputs<Inputs>>];
        method(
          publicInput: PublicInputs<Inputs>,
          privateInput: PrivateInputs<Inputs>
        ): Promise<{ publicOutput: Output }>;
      };
    };
  }>;
};

function createProgram<S extends Spec>(
  spec: S
): Program<GetSpecData<S>, S['inputs']> {
  // split spec inputs into public and private inputs
  let PublicInput = NestedProvable.get(publicInputTypes(spec));
  let PublicOutput = publicOutputType(spec);
  let PrivateInput = NestedProvable.get(privateInputTypes(spec));

  let program = ZkProgram({
    name: programName(spec),
    publicInput: PublicInput,
    publicOutput: PublicOutput,
    methods: {
      run: {
        privateInputs: [PrivateInput],
        async method(
          publicInput: { context: Field; claims: Record<string, any> },
          privateInput: {
            ownerSignature: Signature;
            credentials: Record<string, any>;
          }
        ) {
          let credentials = extractCredentialInputs(
            spec,
            publicInput,
            privateInput
          );
          let credentialOutputs = verifyCredentials(credentials);

          let root = rootValue(
            spec,
            publicInput,
            privateInput,
            credentialOutputs
          );
          let assertion = Node.eval(root, spec.assert);
          let outputClaim = Node.eval(root, spec.outputClaim);
          assertion.assertTrue('Program assertion failed!');
          return { publicOutput: outputClaim };
        },
      },
    },
  });

  let isCompiled = false;
  let verificationKey: VerificationKey | undefined;

  return {
    async compile() {
      if (isCompiled) return verificationKey!;
      let result = await program.compile();
      isCompiled = true;
      verificationKey = result.verificationKey;
      return verificationKey;
    },
    async run(input) {
      let { publicInput, privateInput } = splitUserInputs(input);
      let result = await program.run(publicInput, privateInput);
      return result.proof as any;
    },
    program: program as any,
  };
}

// helper

function programName(spec: Spec): string {
  const serializedSpec = JSON.stringify(serializeSpec(spec));
  const specBytes = Bytes.fromString(serializedSpec);
  const hashBytes = Hash.Keccak256.hash(specBytes);
  return `credential-${hashBytes.toHex().slice(0, 16)}`;
}

type GetSpecData<S extends Spec> = S extends Spec<infer Data, any>
  ? Data
  : never;
