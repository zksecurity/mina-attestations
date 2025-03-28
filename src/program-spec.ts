import {
  Bool,
  Field,
  Signature,
  PublicKey,
  type InferProvable,
  Provable,
  type From,
} from 'o1js';
import type { ExcludeFromRecord } from './types.ts';
import { ProvableType } from './o1js-missing.ts';
import { assert } from './util.ts';
import {
  inferNestedProvable,
  type InferNestedProvable,
  NestedProvable,
  type NestedProvableFor,
} from './nested.ts';
import {
  type CredentialSpec,
  type Credential,
  type CredentialInputs,
  withOwner,
  type CredentialOutputs,
} from './credential.ts';
import {
  type CredentialNode,
  type InputToNode,
  Node,
  Operation,
  root,
} from './operation.ts';

export type {
  PublicInputs,
  PrivateInputs,
  UserInputs,
  RootValue,
  Input,
  Claims,
  RootType,
};
export {
  Spec,
  Claim,
  Constant,
  publicInputTypes,
  publicOutputType,
  privateInputTypes,
  splitUserInputs,
  extractCredentialInputs,
  rootValue,
  isCredentialSpec,
};

type Spec<
  Output = unknown,
  Inputs extends Record<string, Input> = Record<string, Input>
> = {
  inputs: Inputs;
  assert: Node<Bool>;
  outputClaim: Node<Output>;
};

/**
 * Specify a ZkProgram that verifies and selectively discloses data
 */
function Spec<Output, Inputs extends Record<string, Input>>(
  inputs: Inputs,
  spec: (inputs: {
    [K in keyof Inputs]: InputToNode<Inputs[K]>;
  }) => {
    assert?: Node<Bool> | Node<Bool>[];
    outputClaim: Node<Output>;
  }
): Spec<Output, Inputs>;

// variant without data output
function Spec<Inputs extends Record<string, Input>>(
  inputs: Inputs,
  spec: (inputs: {
    [K in keyof Inputs]: InputToNode<Inputs[K]>;
  }) => {
    assert?: Node<Bool> | Node<Bool>[];
  }
): Spec<undefined, Inputs>;

// implementation
function Spec<Output, Inputs extends Record<string, Input>>(
  inputs: Inputs,
  spec: (inputs: {
    [K in keyof Inputs]: InputToNode<Inputs[K]>;
  }) => {
    assert?: Node<Bool> | Node<Bool>[];
    outputClaim?: Node<Output>;
  }
): Spec<Output, Inputs> {
  let rootNode = root(inputs);
  let inputNodes: {
    [K in keyof Inputs]: InputToNode<Inputs[K]>;
  } = {} as any;
  // some special keys are used internally and must not be used as input keys
  ['owner'].forEach((key) =>
    assert(!(key in inputs), `"${key}" is reserved, can't be used in inputs`)
  );

  for (let key in inputs) {
    if (isCredentialSpec(inputs[key])) {
      let credentialType = inputs[key].credentialType;
      let node: CredentialNode = {
        type: 'credential',
        credentialKey: key,
        credentialType,
      };
      inputNodes[key] = node as any;
    } else {
      inputNodes[key] = Operation.property(rootNode, key) as any;
    }
  }
  let logic = spec(inputNodes);
  let assertNode = logic.assert ?? Operation.constant(Bool(true));
  if (Array.isArray(assertNode)) assertNode = Operation.and(...assertNode);

  let outputClaim: Node<Output> =
    logic.outputClaim ?? (Operation.constant(undefined) as any);

  return { inputs, assert: assertNode, outputClaim };
}

type Constant<Data> = {
  type: 'constant';
  data: ProvableType<Data>;
  value: Data;
};
type Claim<Data> = { type: 'claim'; data: NestedProvableFor<Data> };

type Input<Data = any> =
  | (CredentialSpec<any, Data> & { type?: undefined })
  | Constant<Data>
  | Claim<Data>;

function isCredentialSpec(input: Input | undefined): input is CredentialSpec {
  return (
    input !== undefined && input.type !== 'claim' && input.type !== 'constant'
  );
}

function Constant<DataType extends ProvableType>(
  data: DataType,
  value: From<DataType>
): Constant<InferProvable<DataType>> {
  return {
    type: 'constant',
    data,
    value: ProvableType.get(data).fromValue(value),
  };
}

function Claim<DataType extends NestedProvable>(
  data: DataType
): Claim<InferNestedProvable<DataType>> {
  return { type: 'claim', data: inferNestedProvable(data) };
}

// helpers to extract/recombine portions of the spec inputs

function publicInputTypes({ inputs }: Spec): {
  context: typeof Field;
  claims: NestedProvable;
} {
  let claims: Record<string, NestedProvable> = {};

  Object.entries(inputs).forEach(([key, input]) => {
    if (input.type === 'claim') {
      claims[key] = input.data;
    }
  });
  return { context: Field, claims };
}

type CredentialInputType = {
  credential: { owner: PublicKey; data: unknown };
  witness: unknown;
};

function privateInputTypes({ inputs }: Spec): NestedProvableFor<{
  ownerSignature: Signature;
  credentials: Record<string, CredentialInputType>;
}> {
  let credentials: Record<string, NestedProvableFor<CredentialInputType>> = {};

  Object.entries(inputs).forEach(([key, input]) => {
    if (isCredentialSpec(input)) {
      credentials[key] = {
        credential: withOwner(input.data),
        witness: input.witnessType(input.witness),
      };
    }
  });
  return { ownerSignature: Signature, credentials };
}

function publicOutputType(spec: Spec): Provable<unknown> {
  let root = rootType(spec);
  let outputTypeNested = Node.evalType(root, spec.outputClaim);
  return NestedProvable.get(outputTypeNested);
}

type RootType = Record<string, NestedProvable | CredentialSpec>;

function rootType({ inputs }: Spec): RootType {
  let result: Record<string, NestedProvable | CredentialSpec> = {};
  Object.entries(inputs).forEach(([key, input]) => {
    if (isCredentialSpec(input)) {
      result[key] = input;
    } else {
      result[key] = input.data;
    }
  });
  return result;
}

function splitUserInputs<I extends Spec['inputs']>(
  userInputs: UserInputs<I>
): {
  publicInput: PublicInputs<I>;
  privateInput: PrivateInputs<I>;
};
function splitUserInputs({
  context,
  ownerSignature,
  claims,
  credentials,
}: UserInputs<any>) {
  return {
    publicInput: { context, claims },
    privateInput: { ownerSignature, credentials },
  };
}

function extractCredentialInputs(
  spec: Spec,
  { context }: PublicInputs<any>,
  { ownerSignature, credentials }: PrivateInputs<any>
): CredentialInputs {
  let credentialInputs: CredentialInputs['credentials'] = [];

  Object.entries(spec.inputs).forEach(([key, input]) => {
    if (isCredentialSpec(input)) {
      let value: any = credentials[key];
      credentialInputs.push({
        spec: input,
        credential: value.credential,
        witness: value.witness,
      });
    }
  });

  return { context, ownerSignature, credentials: credentialInputs };
}

function rootValue<S extends Spec>(
  spec: S,
  publicInputs: PublicInputs<any>,
  privateInputs: PrivateInputs<any>,
  credentialOutputs: CredentialOutputs
): RootValue<S['inputs']>;
function rootValue<S extends Spec>(
  spec: S,
  { claims }: PublicInputs<any>,
  _: PrivateInputs<any>,
  credentialOutputs: CredentialOutputs
): Record<string, any> {
  let result: Record<string, any> = {};

  let i = 0;

  Object.entries(spec.inputs).forEach(([key, input]) => {
    if (isCredentialSpec(input)) {
      result[key] = credentialOutputs.credentials[i];
      i++;
    }
    if (input.type === 'claim') {
      result[key] = claims[key];
    }
    if (input.type === 'constant') {
      result[key] = input.value;
    }
  });
  result.owner = credentialOutputs.owner;
  return result;
}

type Claims<Inputs extends Record<string, Input>> = ExcludeFromRecord<
  MapToClaims<Inputs>,
  never
>;

type PublicInputs<Inputs extends Record<string, Input>> = {
  context: Field;
  claims: Claims<Inputs>;
};

type Credentials<Inputs extends Record<string, Input>> = ExcludeFromRecord<
  MapToCredentials<Inputs>,
  never
>;

type PrivateInputs<Inputs extends Record<string, Input>> = {
  ownerSignature: Signature;
  credentials: Credentials<Inputs>;
};

type UserInputs<Inputs extends Record<string, Input>> = {
  context: Field;
  ownerSignature: Signature;
  claims: ExcludeFromRecord<MapToClaims<Inputs>, never>;
  credentials: ExcludeFromRecord<MapToCredentials<Inputs>, never>;
};

type RootValue<Inputs extends Record<string, Input> = Record<string, Input>> =
  ExcludeFromRecord<MapToDataInput<Inputs>, never> & { owner: PublicKey };

type MapToClaims<T extends Record<string, Input>> = {
  [K in keyof T]: ToClaim<T[K]>;
};

type MapToCredentials<T extends Record<string, Input>> = {
  [K in keyof T]: ToCredential<T[K]>;
};

type MapToDataInput<T extends Record<string, Input>> = {
  [K in keyof T]: ToDataInput<T[K]>;
};

type ToClaim<T extends Input> = T extends Claim<infer Data> ? Data : never;

type ToCredential<T extends Input> = T extends CredentialSpec<
  infer Witness,
  infer Data
>
  ? { credential: Credential<Data>; witness: Witness }
  : never;

type ToDataInput<T extends Input> = T extends CredentialSpec<
  infer Witness,
  infer Data
>
  ? { data: Data; witness: Witness; issuer: Field }
  : T extends Input<infer Data>
  ? Data
  : never;
