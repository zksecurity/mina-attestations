/**
 * JSON serialization of provable types and values.
 */
import { NestedProvable } from './nested.ts';
import { array, ProvableType } from './o1js-missing.ts';
import {
  Field,
  Bool,
  UInt8,
  UInt32,
  UInt64,
  PublicKey,
  Signature,
  Undefined,
  Bytes,
  DynamicProof,
  VerificationKey,
  Struct,
  type JsonProof,
  Int64,
} from 'o1js';
import { assert, assertHasMethod, defined, mapObject } from './util.ts';
import { ProvableFactory, type SerializedFactory } from './provable-factory.ts';
import type { JSONValue } from './types.ts';

export {
  type O1jsTypeName,
  type SerializedType,
  type SerializedValue,
  type SerializedNestedType,
  supportedTypes,
  serializeProvableType,
  serializeProvable,
  serializeProvableField,
  serializeProvablePublicKey,
  serializeNestedProvable,
  serializeNestedProvableValue,
  deserializeProvableType,
  deserializeProvable,
  deserializeNestedProvable,
  deserializeNestedProvableValue,
  replaceNull,
  replaceUndefined,
};

// Supported o1js base types
const supportedTypes = {
  Field,
  Bool,
  UInt8,
  UInt32,
  UInt64,
  Int64,
  PublicKey,
  Signature,
  Undefined,
  VerificationKey,
};
type O1jsTypeName = keyof typeof supportedTypes;

let mapProvableTypeToName = new Map<ProvableType<any>, O1jsTypeName>();
for (let [key, value] of Object.entries(supportedTypes)) {
  mapProvableTypeToName.set(value, key as O1jsTypeName);
}

type SerializedType =
  | { _type: O1jsTypeName }
  | { _type: 'Struct'; properties: SerializedNestedType }
  | { _type: 'Array'; inner: SerializedType; size: number }
  | { _type: 'Constant'; value: JSONValue }
  | { _type: 'Bytes'; size: number }
  | { _type: 'Proof'; proof: Record<string, any> }
  | { _type: 'String' }
  | SerializedFactory;

type SerializedNestedType =
  | SerializedType
  | { [key: string]: SerializedNestedType };

// SERIALIZE

function serializeProvableType(type: ProvableType<any>): SerializedType {
  let serialized = ProvableFactory.tryToJSON(type);
  if (serialized !== undefined) return serialized;

  if ('serialize' in type && typeof type.serialize === 'function') {
    return type.serialize();
  }
  if ((type as any).prototype instanceof Bytes.Base) {
    return { _type: 'Bytes', size: (type as typeof Bytes.Base).size };
  }
  if ((type as any).prototype instanceof DynamicProof) {
    let { publicInputType, publicOutputType, maxProofsVerified, featureFlags } =
      type as typeof DynamicProof;
    let proof = {
      name: (type as typeof DynamicProof).name,
      publicInput: serializeProvableType(publicInputType),
      publicOutput: serializeProvableType(publicOutputType),
      maxProofsVerified,
      featureFlags: replaceUndefined(featureFlags),
    };
    return { _type: 'Proof', proof };
  }
  let _type = mapProvableTypeToName.get(type);
  if (_type === undefined && (type as any)._isStruct) {
    return serializeStructType(type as Struct<any>);
  }
  if (_type === undefined && (type as any)._isArray) {
    return {
      _type: 'Array',
      inner: serializeProvableType((type as any).innerType),
      size: (type as any).size,
    };
  }
  assert(_type !== undefined, () => {
    console.log('serializeProvableType', type);
    return `serializeProvableType: Unsupported provable type: ${type}`;
  });
  return { _type };
}

type SerializedValue = SerializedType & { value: JSONValue };
type SerializedValueAny = SerializedType & { value: any };

function serializeProvable(value: any): SerializedType & { value: JSONValue } {
  let typeClass = ProvableType.fromValue(value);
  let serializedType = serializeProvableType(typeClass);

  if (ProvableFactory.isSerialized(serializedType)) {
    let serialized = ProvableFactory.tryValueToJSON(value);
    return defined(serialized);
  }

  switch (serializedType._type) {
    case 'Bytes':
      return { ...serializedType, value: (value as Bytes).toHex() };
    case 'Proof':
      let json = (value as DynamicProof<any, any>).toJSON();
      return { ...serializedType, value: json };
    case 'Array': {
      return {
        ...serializedType,
        value: value.map((x: any) => serializeProvable(x)),
      };
    }
    case 'Struct':
      let result: Record<string, any> = {};
      for (let key in serializedType.properties) {
        result[key] = serializeNestedProvableValue(value[key]);
      }
      return { ...serializedType, value: result };
    case 'Undefined':
      return { ...serializedType, value: null };
    case 'Constant':
      return serializedType;
    case 'String':
      return { ...serializedType, value };
    case 'UInt8':
      return { ...serializedType, value: (value as UInt8).toString() };
    case 'VerificationKey':
      let vk: VerificationKey = value;
      return {
        ...serializedType,
        value: { data: vk.data, hash: vk.hash.toString() },
      };
    default:
      assertHasMethod(
        value,
        'toJSON',
        `Missing toJSON method for ${serializedType._type}`
      );
      return { ...serializedType, value: value.toJSON() };
  }
}

// some special cases

function serializeProvableField(value: Field) {
  return { _type: 'Field', value: value.toJSON() } satisfies SerializedValue;
}

function serializeProvablePublicKey(value: PublicKey) {
  return {
    _type: 'PublicKey',
    value: value.toJSON(),
  } satisfies SerializedValue;
}

function serializeStructType(type: Struct<any>): SerializedType {
  let value = type.empty();
  let properties: SerializedNestedType = {};

  for (let key in value) {
    let type = NestedProvable.fromValue(value[key]);
    properties[key] = serializeNestedProvable(type);
  }
  return { _type: 'Struct', properties };
}

function serializeNestedProvable(type: NestedProvable): SerializedNestedType {
  if (ProvableType.isProvableType(type)) {
    return serializeProvableType(type);
  }

  if (typeof type === 'string' || (type as any) === String)
    return { _type: 'String' };

  if (typeof type === 'object' && type !== null) {
    const serializedObject: Record<string, any> = {};
    for (const key of Object.keys(type)) {
      serializedObject[key] = serializeNestedProvable(type[key]!);
    }
    return serializedObject;
  }

  throw Error(`Unsupported type in NestedProvable: ${type}`);
}

function serializeNestedProvableValue(value: any): any {
  let type = NestedProvable.fromValue(value);
  return serializeNestedProvableTypeAndValue({ type, value });
}

function serializeNestedProvableTypeAndValue(t: {
  type: NestedProvable;
  value: any;
}): any {
  if (ProvableType.isProvableType(t.type)) {
    return serializeProvable(t.value);
  }
  if (typeof t.type === 'string' || (t.type as any) === String) return t.value;

  return Object.fromEntries(
    Object.keys(t.type).map((key) => {
      assert(key in t.value, `Missing value for key ${key}`);
      return [
        key,
        serializeNestedProvableTypeAndValue({
          type: (t.type as any)[key],
          value: t.value[key],
        }),
      ];
    })
  );
}

// DESERIALIZE

function deserializeProvableType(type: SerializedType): ProvableType<any> {
  if (ProvableFactory.isSerialized(type)) return ProvableFactory.fromJSON(type);

  if (type._type === 'Constant') {
    return ProvableType.constant((type as any).value);
  }
  if (type._type === 'Bytes') {
    return Bytes(type.size);
  }
  if (type._type === 'Proof') {
    let proof = type.proof;
    let Proof = class extends DynamicProof<any, any> {
      static publicInputType = ProvableType.get(
        deserializeProvableType(proof.publicInput)
      );
      static publicOutputType = ProvableType.get(
        deserializeProvableType(proof.publicOutput)
      );
      static maxProofsVerified = proof.maxProofsVerified;
      static featureFlags = replaceNull(proof.featureFlags) as any;
    };
    Object.defineProperty(Proof, 'name', { value: proof.name });
    return Proof;
  }
  if (type._type === 'Struct') {
    let properties = deserializeNestedProvable(type.properties);
    return Struct(properties);
  }
  if (type._type === 'Array') {
    let inner = deserializeProvableType(type.inner);
    return array(inner, type.size);
  }
  if (type._type === 'String') {
    return String as any;
  }
  let result = supportedTypes[type._type];
  assert(result !== undefined, `Unsupported provable type: ${type._type}`);
  return result;
}

function deserializeProvable(json: SerializedValueAny): any {
  if (ProvableFactory.isSerialized(json))
    return ProvableFactory.valueFromJSON(json);

  let { _type, value } = json;
  switch (json._type) {
    case 'Field':
      return Field.fromJSON(value);
    case 'Bool':
      return Bool.fromJSON(value);
    case 'UInt8':
      return UInt8.fromJSON({ value });
    case 'UInt32':
      return UInt32.fromJSON(value);
    case 'UInt64':
      return UInt64.fromJSON(value);
    case 'Int64':
      return Int64.fromJSON(value);
    case 'PublicKey':
      return PublicKey.fromJSON(value);
    case 'Signature':
      return Signature.fromJSON(value);
    case 'Undefined':
      return undefined;
    case 'VerificationKey':
      return VerificationKey.fromJSON(value);
    case 'Bytes':
      let BytesN = deserializeProvableType(json) as typeof Bytes.Base;
      return BytesN.fromHex(value);
    case 'Proof':
      return proofFromJSONSync(json);
    case 'Array':
      return (value as any[]).map((v) => deserializeProvable(v));
    case 'Struct':
      let type = deserializeProvableType(json) as Struct<any>;
      let result: Record<string, any> = {};
      for (let key in json.properties) {
        result[key] = deserializeNestedProvableValue(value[key]);
      }
      return new type(result);
    case 'Constant':
      return value;
    case 'String':
      return value;
    default:
      json satisfies never;
      throw Error(`Unsupported provable type: ${_type}`);
  }
}

// this only works if `await initializeBindings()` from o1js has been called before
// but this implicit dependency seems better than making every `fromJSON` method async
function proofFromJSONSync(json: {
  _type: 'Proof';
  proof: Record<string, any>;
  value: JsonProof;
}) {
  let Proof = deserializeProvableType(json) as typeof DynamicProof;
  let {
    maxProofsVerified,
    proof: proofString,
    publicInput,
    publicOutput,
  } = json.value;
  let proof = Proof._proofFromBase64(proofString, maxProofsVerified);
  let fields = publicInput.map(Field).concat(publicOutput.map(Field));
  return Proof.provable.fromFields(fields, [
    [],
    [],
    [proof, maxProofsVerified],
  ]);
}

function deserializeNestedProvable(type: any): NestedProvable {
  if (typeof type === 'object' && type !== null) {
    if ('_type' in type) {
      // basic provable type
      return deserializeProvableType(type);
    } else {
      // nested object
      const result: Record<string, any> = {};
      for (const [key, value] of Object.entries(type)) {
        result[key] = deserializeNestedProvable(value);
      }
      return result as NestedProvable;
    }
  }
  throw Error(`Invalid type in NestedProvable: ${type}`);
}

function deserializeNestedProvableValue(value: any): any {
  if (typeof value === 'string') return value;

  if (typeof value === 'object' && value !== null) {
    if ('_type' in value) {
      // basic provable type
      return deserializeProvable(value);
    } else {
      // nested object
      const result: Record<string, any> = {};
      for (let [key, v] of Object.entries(value)) {
        result[key] = deserializeNestedProvableValue(v);
      }
      return result;
    }
  }

  throw Error(`Invalid nested provable value: ${value}`);
}

function replaceNull<Input extends Record<string, JSONValue>>(
  obj: Input
): {
  [K in keyof Input]: Input[K] extends infer T | null
    ? T | undefined
    : Input[K];
} {
  return mapObject(obj, (value) => (value === null ? undefined : value) as any);
}

// `null` is preserved in JSON, but `undefined` is removed
function replaceUndefined<Input extends Record<string, JSONValue | undefined>>(
  obj: Input
): {
  [K in keyof Input]: Input[K] extends infer T | undefined
    ? T | null
    : Input[K];
} {
  return mapObject(obj, (value) => (value === undefined ? null : value) as any);
}
