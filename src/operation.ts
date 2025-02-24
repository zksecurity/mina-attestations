import { Bool, UInt8, UInt32, UInt64, Field, Provable, PublicKey } from 'o1js';
import { ProvableType } from './o1js-missing.ts';
import { assert, assertHasProperty } from './util.ts';
import { NestedProvable } from './nested.ts';
import { DynamicArray } from './dynamic/dynamic-array.ts';
import { DynamicRecord, extractProperty } from './dynamic/dynamic-record.ts';
import { hashDynamicWithPrefix } from './dynamic/dynamic-hash.ts';
import type { Input, RootValue, RootType } from './program-spec.ts';
import type { CredentialSpec, CredentialType } from './credential.ts';
import type { NativeWitness } from './credential-native.ts';
import { Imported, type ImportedWitness } from './credential-imported.ts';

export { Node, Operation };
export { type CredentialNode, type InputToNode, root };

const Operation = {
  owner: { type: 'owner' } as Node<PublicKey>,
  constant<Data>(data: Data): Node<Data> {
    return { type: 'constant', data };
  },

  issuer,
  issuerPublicKey,
  verificationKeyHash,
  publicInput,

  property,
  record,
  equals,
  equalsOneOf,
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
  hashWithPrefix,
  ifThenElse,
  compute,
};

type CredentialNode<Data = any, Witness = WitnessAny> = {
  type: 'credential';
  credentialKey: string;
  credentialType: CredentialType;
  // phantom data
  data?: Data;
  witness?: Witness;
};

type Node<Data = any> =
  | { type: 'constant'; data: Data }
  | { type: 'root'; input: Record<string, Input> }

  // operations to extract credential information
  | { type: 'owner' }
  | CredentialNode<Data>
  | { type: 'issuer'; credentialKey: string }
  | { type: 'issuerPublicKey'; credentialKey: string }
  | { type: 'verificationKeyHash'; credentialKey: string }
  | { type: 'publicInput'; credentialKey: string }

  //
  | { type: 'property'; key: string; inner: Node }
  | { type: 'record'; data: Record<string, Node> }
  | { type: 'equals'; left: Node; right: Node }
  | {
      type: 'equalsOneOf';
      input: Node;
      options: Node[] | Node<any[]> | Node<DynamicArray>;
    }
  | { type: 'lessThan'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'lessThanEq'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'add'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'sub'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'mul'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'div'; left: Node<NumericType>; right: Node<NumericType> }
  | { type: 'and'; inputs: Node<Bool>[] }
  | { type: 'or'; left: Node<Bool>; right: Node<Bool> }
  | { type: 'not'; inner: Node<Bool> }
  | { type: 'hash'; inputs: Node[]; prefix?: string }
  | {
      type: 'ifThenElse';
      condition: Node<Bool>;
      thenNode: Node;
      elseNode: Node;
    }
  | {
      type: 'compute';
      inputs: readonly Node[];
      computation: (...inputs: any[]) => any;
      outputType: ProvableType;
    };

type GetData<T extends Input> = T extends Input<infer Data> ? Data : never;

type InputToNode<T extends Input> = T extends CredentialSpec<
  infer Witness,
  infer Data
>
  ? CredentialNode<Data, Witness>
  : Node<GetData<T>>;

const Node = {
  eval: evalNode,
  evalType: evalNodeType,
};

function evalNode<Data>(root: RootValue, node: Node<Data>): Data {
  switch (node.type) {
    case 'constant':
      return node.data;
    case 'root':
      return root as Data;

    // credential operations
    case 'owner':
      return root.owner as Data;
    case 'credential':
      return assertCredential(root, node).data;
    case 'issuer':
      return assertCredential(root, node).issuer as Data;
    case 'issuerPublicKey':
      return assertNativeCredential(root, node).witness.issuer as Data;
    case 'verificationKeyHash':
      return assertImportedCredential(root, node).witness.vk.hash as Data;
    case 'publicInput':
      return assertImportedCredential(root, node).witness.proof
        .publicInput as Data;

    case 'property': {
      let inner = evalNode<unknown>(root, node.inner);
      return extractProperty(inner, node.key) as Data;
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
    case 'equalsOneOf': {
      let input = evalNode(root, node.input);
      let type = NestedProvable.get(NestedProvable.fromValue(input));
      let options: any[] | DynamicArray;
      if (Array.isArray(node.options)) {
        options = node.options.map((i) => evalNode(root, i));
      } else {
        options = evalNode<any[] | DynamicArray>(root, node.options);
      }
      if (options instanceof DynamicArray.Base) {
        let bool = options.reduce(Bool, Bool(false), (acc, o) =>
          acc.or(Provable.equal(type, input, o))
        );
        return bool as Data;
      }
      let bools = options.map((o) => Provable.equal(type, input, o));
      return bools.reduce(Bool.or) as Data;
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
      let inputs = node.inputs.map((i) => evalNode(root, i));
      return inputs.reduce(Bool.and) as Data;
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
    case 'hash': {
      let inputs = node.inputs.map((i) => evalNode(root, i));
      return hashDynamicWithPrefix(node.prefix, ...inputs) as Data;
    }
    case 'ifThenElse': {
      let condition = evalNode(root, node.condition);
      let thenNode = evalNode(root, node.thenNode);
      let elseNode = evalNode(root, node.elseNode);
      let result = Provable.if(condition, thenNode, elseNode);
      return result as Data;
    }
    case 'compute': {
      const computationInputs = node.inputs.map((input) =>
        evalNode(root, input)
      );
      return node.computation(...computationInputs);
    }
  }
}

function arithmeticOperation(
  root: RootValue,
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
  root: RootValue,
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

function evalNodeType(rootType: RootType, node: Node): NestedProvable {
  switch (node.type) {
    case 'constant':
      return ProvableType.fromValue(node.data);
    case 'root':
      return rootType as NestedProvable;

    // credential operations
    case 'owner':
      return PublicKey;
    case 'credential':
      return assertCredentialType(rootType, node).data;
    case 'issuer':
      return Field;
    case 'issuerPublicKey':
      return PublicKey;
    case 'verificationKeyHash':
      return Field;
    case 'publicInput': {
      let spec = assertCredentialType(rootType, node);
      return Imported.publicInputType(spec);
    }

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
    case 'equalsOneOf':
    case 'lessThan':
    case 'lessThanEq':
    case 'and':
    case 'or':
    case 'not':
      return Bool;
    case 'hash':
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
    case 'compute': {
      return node.outputType;
    }
  }
}

function ArithmeticOperationType(
  rootType: RootType,
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

// Node constructors

function root<Inputs extends Record<string, Input>>(
  inputs: Inputs
): Node<{ [K in keyof Inputs]: Node<GetData<Inputs[K]>> }> {
  return { type: 'root', input: inputs };
}

function property<K extends string, Data extends { [key in K]: any }>(
  node: Node<Data | DynamicRecord<Data>>,
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

function equalsOneOf<Data>(
  input: Node<Data>,
  options: Node<Data>[] | Node<Data[]> | Node<DynamicArray<Data>>
): Node<Bool> {
  return { type: 'equalsOneOf', input, options };
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

function and(...inputs: Node<Bool>[]): Node<Bool> {
  return { type: 'and', inputs };
}

function or(left: Node<Bool>, right: Node<Bool>): Node<Bool> {
  return { type: 'or', left, right };
}

function not(inner: Node<Bool>): Node<Bool> {
  return { type: 'not', inner };
}

function hash(...inputs: Node[]): Node<Field> {
  return { type: 'hash', inputs };
}
function hashWithPrefix(prefix: string, ...inputs: Node[]): Node<Field> {
  return { type: 'hash', inputs, prefix };
}

function ifThenElse<Data>(
  condition: Node<Bool>,
  thenNode: Node<Data>,
  elseNode: Node<Data>
): Node<Data> {
  return { type: 'ifThenElse', condition, thenNode, elseNode };
}

function compute<Inputs extends readonly Node[], Output>(
  inputs: [...Inputs],
  outputType: ProvableType<Output>,
  computation: (
    ...args: {
      [K in keyof Inputs]: Inputs[K] extends Node<infer T> ? T : never;
    }
  ) => Output
): Node<Output> {
  return {
    type: 'compute',
    inputs: inputs,
    computation: computation as (inputs: any[]) => Output,
    outputType,
  };
}

// credential operations

function issuer(credential: CredentialNode): Node<Field> {
  return { type: 'issuer', credentialKey: credential.credentialKey };
}

function issuerPublicKey({
  credentialType,
  credentialKey,
}: CredentialNode<any, NativeWitness>): Node<PublicKey> {
  assert(
    credentialType === 'native',
    '`issuerPublicKey` is only available on signed credentials'
  );
  return { type: 'issuerPublicKey', credentialKey };
}

function verificationKeyHash({
  credentialType,
  credentialKey,
}: CredentialNode<any, ImportedWitness>): Node<Field> {
  assert(
    credentialType === 'imported',
    '`verificationKeyHash` is only available on imported credentials'
  );
  return { type: 'verificationKeyHash', credentialKey };
}

function publicInput<Input>({
  credentialType,
  credentialKey,
}: CredentialNode<any, ImportedWitness<Input>>): Node<Input> {
  assert(
    credentialType === 'imported',
    '`publicInput` is only available on imported credentials'
  );
  return { type: 'publicInput', credentialKey };
}

type WitnessAny = NativeWitness | ImportedWitness | undefined;

type CredentialOutput<Data = any, Witness extends WitnessAny = WitnessAny> = {
  data: Data;
  issuer: Field;
  witness: Witness;
};
type CredentialOutputNative<Data = any> = CredentialOutput<Data, NativeWitness>;
type CredentialOutputImported<Data = any> = CredentialOutput<
  Data,
  ImportedWitness
>;

type CredentialNodeType =
  | 'credential'
  | 'issuer'
  | 'issuerPublicKey'
  | 'verificationKeyHash'
  | 'publicInput';

function assertCredential<Data>(
  root: RootValue,
  credential: Node<Data> & { type: CredentialNodeType }
) {
  assertHasProperty(root, credential.credentialKey);
  return root[credential.credentialKey] as CredentialOutput<Data>;
}

function assertCredentialType<Data>(
  rootType: Record<string, NestedProvable | CredentialSpec>,
  credential: Node<Data> & { type: CredentialNodeType }
) {
  assertHasProperty(rootType, credential.credentialKey);
  return rootType[credential.credentialKey] as CredentialSpec;
}

function assertNativeCredential<Data>(
  root: RootValue,
  credential: Node<Data> & { type: CredentialNodeType }
) {
  let cred = assertCredential(root, credential);
  assert(cred.witness?.type === 'native');
  return cred as CredentialOutputNative<Data>;
}

function assertImportedCredential<Data>(
  root: RootValue,
  credential: Node<Data> & { type: CredentialNodeType }
) {
  let cred = assertCredential(root, credential);
  assert(cred.witness?.type === 'imported');
  return cred as CredentialOutputImported<Data>;
}
