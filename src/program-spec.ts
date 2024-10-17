import {
  Bool,
  UInt8,
  UInt32,
  UInt64,
  Field,
  Provable,
  type ProvablePure,
  Poseidon,
  Signature,
  PublicKey,
} from 'o1js';
import type { ExcludeFromRecord } from './types.ts';
import {
  assertPure,
  type InferProvableType,
  ProvableType,
} from './o1js-missing.ts';
import { assertHasProperty } from './util.ts';
import {
  type InferNestedProvable,
  NestedProvable,
  type NestedProvableFor,
  type NestedProvablePure,
  type NestedProvablePureFor,
} from './nested.ts';
import {
  type CredentialType,
  type CredentialId,
  Credential,
  type CredentialInputs,
  type CredentialOutputs,
} from './credentials.ts';

export type { PublicInputs, UserInputs, DataInputs };
export {
  Spec,
  Node,
  Operation,
  Input,
  publicInputTypes,
  publicOutputType,
  privateInputTypes,
  splitUserInputs,
  extractCredentialInputs,
  recombineDataInputs,
};

type Spec<
  Data = any,
  Inputs extends Record<string, Input> = Record<string, Input>
> = {
  inputs: Inputs;
  logic: Required<OutputNode<Data>>;
};

/**
 * Specify a ZkProgram that verifies and selectively discloses data
 */
function Spec<Data, Inputs extends Record<string, Input>>(
  inputs: Inputs,
  spec: (inputs: {
    [K in keyof Inputs]: Node<GetData<Inputs[K]>>;
  }) => {
    assert?: Node<Bool>;
    data: Node<Data>;
  }
): Spec<Data, Inputs>;

// variant without data output
function Spec<Inputs extends Record<string, Input>>(
  inputs: Inputs,
  spec: (inputs: {
    [K in keyof Inputs]: Node<GetData<Inputs[K]>>;
  }) => {
    assert?: Node<Bool>;
  }
): Spec<undefined, Inputs>;

// implementation
function Spec<Data, Inputs extends Record<string, Input>>(
  inputs: Inputs,
  spec: (inputs: {
    [K in keyof Inputs]: Node<GetData<Inputs[K]>>;
  }) => OutputNode<Data>
): Spec<Data, Inputs> {
  let rootNode = root(inputs);
  let inputNodes: {
    [K in keyof Inputs]: Node<GetData<Inputs[K]>>;
  } = {} as any;
  for (let key in inputs) {
    if (inputs[key]!.type === 'credential') {
      let credential = property(rootNode, key) as any;
      let data = property(credential, 'data') as any;
      inputNodes[key] = data;
    } else {
      inputNodes[key] = property(rootNode, key) as any;
    }
  }
  let logic = spec(inputNodes);
  let assert = logic.assert ?? Node.constant(Bool(true));
  let data: Node<Data> = logic.data ?? (Node.constant(undefined) as any);

  return { inputs, logic: { assert, data } };
}

const Input = { claim, constant };

const Operation = {
  owner,
  issuer,
  property,
  record,
  equals,
  lessThan,
  lessThanEq,
  add,
  sub,
  mul,
  div,
  and,
  or,
  not,
  hash,
  ifThenElse,
};

type Constant<Data> = {
  type: 'constant';
  data: ProvableType<Data>;
  value: Data;
};
type Claim<Data> = { type: 'claim'; data: NestedProvablePureFor<Data> };

type Input<Data = any> =
  | CredentialType<CredentialId, any, Data>
  | Constant<Data>
  | Claim<Data>;

type Node<Data = any> =
  | { type: 'owner' }
  | { type: 'issuer'; credentialKey: string }
  | { type: 'constant'; data: Data }
  | { type: 'root'; input: Record<string, Input> }
  | { type: 'property'; key: string; inner: Node }
  | { type: 'record'; data: Record<string, Node> }
  | { type: 'equals'; left: Node; right: Node }
  | { type: 'lessThan'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'lessThanEq'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'add'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'sub'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'mul'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'div'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'and'; left: Node<Bool>; right: Node<Bool> }
  | { type: 'or'; left: Node<Bool>; right: Node<Bool> }
  | { type: 'not'; inner: Node<Bool> }
  | { type: 'hash'; inner: Node }
  | {
      type: 'ifThenElse';
      condition: Node<Bool>;
      thenNode: Node;
      elseNode: Node;
    };

type OutputNode<Data = any> = {
  assert?: Node<Bool>;
  data?: Node<Data>;
};

const Node = {
  eval: evalNode,
  evalType: evalNodeType,

  constant<Data>(data: Data): Node<Data> {
    return { type: 'constant', data };
  },
};

function evalNode<Data>(root: object, node: Node<Data>): Data {
  switch (node.type) {
    case 'owner':
      return (root as any).owner;
    case 'issuer':
      assertHasProperty(root, node.credentialKey);
      const credential = (root as any)[node.credentialKey];
      return credential.issuer;
    case 'constant':
      return node.data;
    case 'root':
      return root as any;
    case 'property': {
      let inner = evalNode<unknown>(root, node.inner);
      if (inner && typeof inner === 'object' && 'credential' in inner) {
        assertHasProperty(inner.credential, node.key);
        return inner.credential[node.key] as Data;
      } else {
        assertHasProperty(inner, node.key);
        return inner[node.key] as Data;
      }
    }
    case 'record': {
      let result: Record<string, any> = {};
      for (let key in node.data) {
        result[key] = evalNode(root, node.data[key]!);
      }
      return result as any;
    }
    case 'equals': {
      let left = evalNode(root, node.left);
      let right = evalNode(root, node.right);
      let bool = Provable.equal(ProvableType.fromValue(left), left, right);
      return bool as Data;
    }
    case 'lessThan':
    case 'lessThanEq':
      return compareNodes(root, node, node.type === 'lessThanEq') as Data;
    case 'add':
    case 'sub':
    case 'mul':
    case 'div':
      return arithmeticOperation(root, node) as Data;
    case 'and': {
      let left = evalNode(root, node.left);
      let right = evalNode(root, node.right);
      return left.and(right) as Data;
    }
    case 'or': {
      let left = evalNode(root, node.left);
      let right = evalNode(root, node.right);
      return left.or(right) as Data;
    }
    case 'not': {
      let inner = evalNode(root, node.inner);
      return inner.not() as Data;
    }
    // TODO: handle composite types
    case 'hash': {
      let inner = evalNode(root, node.inner);
      let innerFields = inner.toFields();
      let hash = Poseidon.hash(innerFields);
      return hash as Data;
    }
    case 'ifThenElse': {
      let condition = evalNode(root, node.condition);
      let thenNode = evalNode(root, node.thenNode);
      let elseNode = evalNode(root, node.elseNode);
      let result = Provable.if(condition, thenNode, elseNode);
      return result as Data;
    }
  }
}

function arithmeticOperation(
  root: object,
  node: {
    type: 'add' | 'sub' | 'mul' | 'div';
    left: Node<NumericType>;
    right: Node<NumericType>;
  }
): NumericType {
  let left = evalNode(root, node.left);
  let right = evalNode(root, node.right);

  const [leftConverted, rightConverted] = convertNodes(left, right);

  switch (node.type) {
    case 'add':
      return leftConverted.add(rightConverted as any);
    case 'sub':
      return leftConverted.sub(rightConverted as any);
    case 'mul':
      return leftConverted.mul(rightConverted as any);
    case 'div':
      return leftConverted.div(rightConverted as any);
  }
}

function compareNodes(
  root: object,
  node: { left: Node<any>; right: Node<any> },
  allowEqual: boolean
): Bool {
  let left = evalNode(root, node.left);
  let right = evalNode(root, node.right);

  const [leftConverted, rightConverted] = convertNodes(left, right);

  return allowEqual
    ? leftConverted.lessThanOrEqual(rightConverted as any)
    : leftConverted.lessThan(rightConverted as any);
}

function convertNodes(left: any, right: any): [NumericType, NumericType] {
  const leftTypeIndex = numericTypeOrder.findIndex(
    (type) => left instanceof type
  );
  const rightTypeIndex = numericTypeOrder.findIndex(
    (type) => right instanceof type
  );

  const resultType = numericTypeOrder[Math.max(leftTypeIndex, rightTypeIndex)];

  const leftConverted =
    leftTypeIndex < rightTypeIndex
      ? resultType === Field
        ? left.toField()
        : resultType === UInt64
        ? left.toUInt64()
        : left.toUInt32()
      : left;

  const rightConverted =
    leftTypeIndex > rightTypeIndex
      ? resultType === Field
        ? right.toField()
        : resultType === UInt64
        ? right.toUInt64()
        : right.toUInt32()
      : right;

  return [leftConverted, rightConverted];
}

function evalNodeType(rootType: NestedProvable, node: Node): NestedProvable {
  switch (node.type) {
    case 'constant':
      return ProvableType.fromValue(node.data);
    case 'root':
      return rootType;
    case 'property': {
      // TODO would be nice to get inner types of structs more easily
      let inner = evalNodeType(rootType, node.inner);

      // case 1: inner is a provable type
      if (ProvableType.isProvableType(inner)) {
        let innerValue = ProvableType.synthesize(inner);
        assertHasProperty(innerValue, node.key);
        let value = innerValue[node.key];
        return ProvableType.fromValue(value);
      }
      // case 2: inner is a record of provable types
      return inner[node.key] as any;
    }
    case 'equals':
    case 'lessThan':
    case 'lessThanEq':
    case 'and':
    case 'or':
    case 'not':
      return Bool;
    case 'owner':
      return PublicKey;
    case 'hash':
    case 'issuer':
      return Field;
    case 'add':
    case 'sub':
    case 'mul':
    case 'div':
      return ArithmeticOperationType(rootType, node);
    case 'ifThenElse':
      return Node as any;
    case 'record': {
      let result: Record<string, NestedProvable> = {};
      for (let key in node.data) {
        result[key] = evalNodeType(rootType, node.data[key]!);
      }
      return result;
    }
  }
}

function ArithmeticOperationType(
  rootType: NestedProvable,
  node: { left: Node<NumericType>; right: Node<NumericType> }
): NestedProvable {
  const leftType = evalNodeType(rootType, node.left);
  const rightType = evalNodeType(rootType, node.right);
  const leftTypeIndex = numericTypeOrder.findIndex((type) => leftType === type);
  const rightTypeIndex = numericTypeOrder.findIndex(
    (type) => rightType === type
  );
  return numericTypeOrder[Math.max(leftTypeIndex, rightTypeIndex)] as any;
}

type GetData<T extends Input> = T extends Input<infer Data> ? Data : never;

function constant<DataType extends ProvableType>(
  data: DataType,
  value: InferProvableType<DataType>
): Constant<InferProvableType<DataType>> {
  return { type: 'constant', data, value };
}

function claim<DataType extends NestedProvablePure>(
  data: DataType
): Claim<InferNestedProvable<DataType>> {
  return { type: 'claim', data: data as any };
}

// Node constructors

function root<Inputs extends Record<string, Input>>(
  inputs: Inputs
): Node<{ [K in keyof Inputs]: Node<GetData<Inputs[K]>> }> {
  return { type: 'root', input: inputs };
}

function property<K extends string, Data extends { [key in K]: any }>(
  node: Node<Data>,
  key: K
): Node<Data[K]> {
  return { type: 'property', key, inner: node as Node<any> };
}

function record<Nodes extends Record<string, Node>>(
  nodes: Nodes
): Node<{
  [K in keyof Nodes]: Nodes[K] extends Node<infer Data> ? Data : never;
}> {
  return { type: 'record', data: nodes };
}

function equals<Data>(left: Node<Data>, right: Node<Data>): Node<Bool> {
  return { type: 'equals', left, right };
}

type NumericType = Field | UInt64 | UInt32 | UInt8;

const numericTypeOrder = [UInt8, UInt32, UInt64, Field];

function lessThan<Left extends NumericType, Right extends NumericType>(
  left: Node<Left>,
  right: Node<Right>
): Node<Bool> {
  return { type: 'lessThan', left, right };
}

function lessThanEq<Left extends NumericType, Right extends NumericType>(
  left: Node<Left>,
  right: Node<Right>
): Node<Bool> {
  return { type: 'lessThanEq', left, right };
}

function add<Left extends NumericType, Right extends NumericType>(
  left: Node<Left>,
  right: Node<Right>
): Node<Left | Right> {
  return { type: 'add', left, right };
}

function sub<Left extends NumericType, Right extends NumericType>(
  left: Node<Left>,
  right: Node<Right>
): Node<Left | Right> {
  return { type: 'sub', left, right };
}

function mul<Left extends NumericType, Right extends NumericType>(
  left: Node<Left>,
  right: Node<Right>
): Node<Left | Right> {
  return { type: 'mul', left, right };
}

function div<Left extends NumericType, Right extends NumericType>(
  left: Node<Left>,
  right: Node<Right>
): Node<Left | Right> {
  return { type: 'div', left, right };
}

function and(left: Node<Bool>, right: Node<Bool>): Node<Bool> {
  return { type: 'and', left, right };
}

function or(left: Node<Bool>, right: Node<Bool>): Node<Bool> {
  return { type: 'or', left, right };
}

function not(inner: Node<Bool>): Node<Bool> {
  return { type: 'not', inner };
}

function hash(inner: Node): Node<Field> {
  return { type: 'hash', inner };
}

function owner(): Node<PublicKey> {
  return { type: 'owner' };
}

function issuer(credentialKey: string): Node<Field> {
  return { type: 'issuer', credentialKey };
}

function ifThenElse<Data>(
  condition: Node<Bool>,
  thenNode: Node<Data>,
  elseNode: Node<Data>
): Node<Data> {
  return { type: 'ifThenElse', condition, thenNode, elseNode };
}

// helpers to extract/recombine portions of the spec inputs

function publicInputTypes({ inputs }: Spec): NestedProvablePureFor<{
  context: Field;
  claims: Record<string, any>;
}> {
  let result: Record<string, NestedProvablePure> = {};

  Object.entries(inputs).forEach(([key, input]) => {
    if (input.type === 'claim') {
      result[key] = input.data;
    }
  });
  return {
    context: Field,
    claims: result,
  };
}

function privateInputTypes({ inputs }: Spec): NestedProvableFor<{
  ownerSignature: Signature;
  privateCredentialInputs: Record<string, any>;
}> {
  let credentials: Record<string, NestedProvable> = {};

  Object.entries(inputs).forEach(([key, input]) => {
    if (input.type === 'credential') {
      credentials[key] = {
        credential: Credential.withOwner(input.data),
        private: input.private,
      };
    }
  });
  return {
    ownerSignature: Signature,
    privateCredentialInputs: credentials,
  };
}

function publicOutputType<S extends Spec>(spec: S): ProvablePure<any> {
  let root = dataInputTypes(spec);
  let outputTypeNested = Node.evalType(root, spec.logic.data);
  let outputType = NestedProvable.get(outputTypeNested);
  assertPure(outputType);
  return outputType;
}

function dataInputTypes<S extends Spec>({ inputs }: S): NestedProvable {
  let result: Record<string, NestedProvable> = {};
  Object.entries(inputs).forEach(([key, input]) => {
    if (input.type === 'credential') {
      result[key] = Credential.withOwner(input.data);
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
    privateInput: { ownerSignature, privateCredentialInputs: credentials },
  };
}

function extractCredentialInputs(
  spec: Spec,
  { context }: PublicInputs<any>,
  { ownerSignature, privateCredentialInputs }: PrivateInputs<any>
): CredentialInputs {
  let credentials: CredentialInputs['credentials'] = [];

  Object.entries(spec.inputs).forEach(([key, input]) => {
    if (input.type === 'credential') {
      let value: any = privateCredentialInputs[key];
      credentials.push({
        credentialType: input,
        credential: value.credential,
        privateInput: value.private,
      });
    }
  });

  return { context, ownerSignature, credentials };
}

function recombineDataInputs<S extends Spec>(
  spec: S,
  publicInputs: PublicInputs<any>,
  privateInputs: PrivateInputs<any>,
  credentialOutputs: CredentialOutputs
): DataInputs<S['inputs']>;
function recombineDataInputs<S extends Spec>(
  spec: S,
  { claims }: PublicInputs<any>,
  { privateCredentialInputs }: PrivateInputs<any>,
  credentialOutputs: CredentialOutputs
): Record<string, any> {
  let result: Record<string, any> = {};

  let i = 0;

  Object.entries(spec.inputs).forEach(([key, input]) => {
    if (input.type === 'credential') {
      result[key] = {
        credential: (privateCredentialInputs[key] as any).credential,
        issuer: credentialOutputs.credentials[i]!.issuer,
      };
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

type PublicInputs<Inputs extends Record<string, Input>> = {
  context: Field;
  claims: ExcludeFromRecord<MapToClaims<Inputs>, never>;
};

type PrivateInputs<Inputs extends Record<string, Input>> = {
  ownerSignature: Signature;
  privateCredentialInputs: ExcludeFromRecord<MapToCredentials<Inputs>, never>;
};

type UserInputs<Inputs extends Record<string, Input>> = {
  context: Field;
  ownerSignature: Signature;
  claims: ExcludeFromRecord<MapToClaims<Inputs>, never>;
  credentials: ExcludeFromRecord<MapToCredentials<Inputs>, never>;
};

type DataInputs<Inputs extends Record<string, Input>> = ExcludeFromRecord<
  MapToDataInput<Inputs>,
  never
>;

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

type ToCredential<T extends Input> = T extends CredentialType<
  CredentialId,
  infer Private,
  infer Data
>
  ? { credential: Credential<Data>; private: Private }
  : never;

type ToDataInput<T extends Input> = T extends CredentialType<
  CredentialId,
  any,
  infer Data
>
  ? Credential<Data>
  : T extends Input<infer Data>
  ? Data
  : never;
