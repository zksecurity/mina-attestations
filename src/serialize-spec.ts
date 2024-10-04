import { type NestedProvableFor } from './nested.ts';
import { ProvableType } from './o1js-missing.ts';
import { Spec, Input, Node } from './program-config.ts';
import {
  Field,
  Bool,
  UInt8,
  UInt32,
  UInt64,
  PublicKey,
  Signature,
  Provable,
  Struct,
} from 'o1js';

// Supported o1js base types
const O1jsType = {
  Field: 'Field',
  Bool: 'Bool',
  UInt8: 'UInt8',
  UInt32: 'UInt32',
  UInt64: 'UInt64',
  PublicKey: 'PublicKey',
  Signature: 'Signature',
} as const;

type O1jsTypeName = (typeof O1jsType)[keyof typeof O1jsType];

const supportedTypes: Record<O1jsTypeName, Provable<any>> = {
  [O1jsType.Field]: Field,
  [O1jsType.Bool]: Bool,
  [O1jsType.UInt8]: UInt8,
  [O1jsType.UInt32]: UInt32,
  [O1jsType.UInt64]: UInt64,
  [O1jsType.PublicKey]: PublicKey,
  [O1jsType.Signature]: Signature,
};

// TODO: only export serializeSpec, deserializeSpec and hashing
export {
  serializeProvableType,
  serializeNestedProvableFor,
  convertNodeToSerializable,
  convertInputToSerializable,
  convertSpecToSerializable,
  serializeSpec,
};

// TODO: simplify and unify serialization
// like maybe instead of data: {type: 'Field'} it can be data: data: 'Field' idk, will figure out
// TODO: Bytes?
function serializeSpec(spec: Spec): string {
  return JSON.stringify(convertSpecToSerializable(spec), null, 2);
}

// TODO: test
function convertSpecToSerializable(spec: Spec): Record<string, any> {
  return {
    inputs: Object.fromEntries(
      // sort by keys so we always get the same serialization for the same spec
      // will be important for hashing
      Object.entries(spec.inputs)
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([key, input]) => [key, convertInputToSerializable(input)])
    ),
    logic: {
      assert: convertNodeToSerializable(spec.logic.assert),
      data: convertNodeToSerializable(spec.logic.data),
    },
  };
}

// TODO: test
function convertInputToSerializable(input: Input): any {
  if ('type' in input) {
    switch (input.type) {
      case 'attestation': {
        return {
          type: 'attestation',
          id: input.id,
          public: serializeProvableType(input.public),
          private: serializeProvableType(input.private),
          data: serializeNestedProvableFor(input.data),
        };
      }
      case 'constant': {
        return {
          type: 'constant',
          data: serializeProvableType(input.data),
          value: serializeProvable(input.value).value,
        };
      }
      case 'public': {
        return {
          type: 'public',
          data: serializeNestedProvableFor(input.data),
        };
      }
      case 'private': {
        return {
          type: 'private',
          data: serializeNestedProvableFor(input.data),
        };
      }
    }
  }
  throw new Error('Invalid input type');
}

function convertNodeToSerializable(node: Node): any {
  switch (node.type) {
    case 'constant': {
      return {
        type: 'constant',
        data: serializeProvable(node.data),
      };
    }
    case 'root': {
      return {
        type: 'root',
        input: Object.fromEntries(
          // sort by keys so we always get the same serialization for the same spec
          // will be important for hashing
          Object.entries(node.input)
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([key, input]) => [key, convertInputToSerializable(input)])
        ),
      };
    }
    case 'property': {
      return {
        type: 'property',
        key: node.key,
        inner: convertNodeToSerializable(node.inner),
      };
    }
    case 'equals':
    case 'lessThan':
    case 'lessThanEq':
    case 'and':
      return {
        type: node.type,
        left: convertNodeToSerializable(node.left),
        right: convertNodeToSerializable(node.right),
      };
  }
}

function serializeProvableType(type: ProvableType<any>): Record<string, any> {
  // TODO: handle case when type is a Struct
  for (const [typeName, provableType] of Object.entries(supportedTypes)) {
    if (type === provableType) {
      return { type: typeName };
    }
  }
  throw new Error(`Unsupported provable type: ${type}`);
}

// Type guard functions
function isField(value: any): value is Field {
  return value instanceof Field;
}

function isBool(value: any): value is Bool {
  return value instanceof Bool;
}

function isUInt8(value: any): value is UInt8 {
  return value instanceof UInt8;
}

function isUInt32(value: any): value is UInt32 {
  return value instanceof UInt32;
}

function isUInt64(value: any): value is UInt64 {
  return value instanceof UInt64;
}

function isPublicKey(value: any): value is PublicKey {
  return value instanceof PublicKey;
}

function isSignature(value: any): value is Signature {
  return value instanceof Signature;
}

// TODO: there must be a simpler way
// I did it this way because I couldn't check the type of the value using instanceof
function serializeProvable(provable: Provable<any>): {
  type: O1jsTypeName;
  value: string;
} {
  const value = ProvableType.get(provable);
  if (isField(value)) return { type: 'Field', value: value.toString() };
  if (isBool(value))
    return { type: 'Bool', value: value.toBoolean().toString() };
  if (isUInt8(value)) return { type: 'UInt8', value: value.toString() };
  if (isUInt32(value)) return { type: 'UInt32', value: value.toString() };
  if (isUInt64(value)) return { type: 'UInt64', value: value.toString() };
  if (isPublicKey(value)) return { type: 'PublicKey', value: value.toBase58() };
  if (isSignature(value)) return { type: 'Signature', value: value.toJSON() };
  throw new Error(`Unsupported Provable: ${value.constructor.name}`);
}

function serializeNestedProvableFor(
  type: NestedProvableFor<any>
): Record<string, any> {
  if (ProvableType.isProvableType(type)) {
    return serializeProvableType(type);
  }

  if (typeof type === 'object' && type !== null) {
    const serializedObject: Record<string, any> = {};
    // sort by keys so we always get the same serialization for the same spec
    // will be important for hashing
    for (const [key, value] of Object.entries(type).sort((a, b) =>
      a[0].localeCompare(b[0])
    )) {
      serializedObject[key] = serializeNestedProvableFor(value);
    }
    return serializedObject;
  }

  throw new Error(`Unsupported type in NestedProvableFor: ${type}`);
}
