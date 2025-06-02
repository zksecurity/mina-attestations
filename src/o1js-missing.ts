/**
 * This file exports types and functions that actually should be exported from o1js
 */
import {
  Bool,
  Field,
  type InferProvable,
  type InferValue,
  Poseidon,
  Provable,
  type ProvableHashable,
  type ProvablePure,
  Struct,
  Undefined,
} from 'o1js';
import { assert, assertHasProperty, hasProperty } from './util.ts';
import type { NestedProvable } from './nested.ts';
import type { Json } from './types.ts';

export {
  ProvableType,
  assertPure,
  type ProvablePureType,
  type ProvableHashableType,
  type ProvableHashablePure,
  type ProvableHashableWide,
  array,
  toFieldsPacked,
  hashPacked,
  empty,
  toInput,
  HashInput,
};

const ProvableType = {
  get<A extends WithProvable<any>>(type: A): ToProvable<A> {
    return (
      hasProperty(type, 'provable') ? type.provable : type
    ) as ToProvable<A>;
  },

  // TODO o1js should make sure this is possible for _all_ provable types
  fromValue<T>(value: T): ProvableHashableType<T> {
    if (value === undefined) return Undefined as any;
    if (value instanceof Field) return Field as any;
    if (value instanceof Bool) return Bool as any;
    if (Array.isArray(value))
      return array(ProvableType.fromValue(value[0]), value.length) as any;

    assertHasProperty(
      value,
      'constructor',
      'Encountered provable value without a constructor: Cannot obtain provable type.'
    );
    let constructor = value.constructor;
    assertIsProvable(ProvableType.get(constructor));
    return constructor as any;
  },

  synthesize<T>(type_: ProvableType<T>): T {
    let type = ProvableType.get(type_);
    let fields = Array.from({ length: type.sizeInFields() }, () => Field(0));
    return type.fromFields(fields, type.toAuxiliary());
  },

  isProvableType(type: unknown): type is ProvableType {
    let type_ = ProvableType.get(type);
    return hasProperty(type_, 'toFields') && hasProperty(type_, 'fromFields');
  },

  isProvableHashableType(type: unknown): type is ProvableHashableType {
    let type_ = ProvableType.get(type);
    return (
      ProvableType.isProvableType(type_) &&
      hasProperty(type_, 'toInput') &&
      hasProperty(type_, 'empty')
    );
  },

  constant<const T extends Json>(
    value: T
  ): ProvablePure<T, T> & { serialize(): any } {
    return {
      serialize() {
        return { _type: 'Constant', value };
      },
      sizeInFields: () => 0,
      toFields: () => [],
      fromFields: () => value,
      toValue: (v) => v,
      fromValue: (v) => v,
      toAuxiliary: () => [],
      check() {},
    };
  },
};

function assertPure<T>(type_: Provable<T>): asserts type_ is ProvablePure<T>;
function assertPure<T>(
  type: ProvableType<T>
): asserts type is ProvablePureType<T>;
function assertPure<T>(
  type: ProvableType<T>
): asserts type is ProvablePureType<T> {
  let aux = ProvableType.get(type).toAuxiliary();
  assert(
    lengthRecursive(aux) === 0,
    'Expected pure provable type to have no auxiliary fields'
  );
}

type NestedArray = any[] | NestedArray[];

function lengthRecursive(array: NestedArray): number {
  if (!Array.isArray(array)) return 1;
  let length = 0;
  for (let i = 0; i < array.length; i++) {
    length += lengthRecursive(array[i]);
  }
  return length;
}

function assertIsProvable(
  type: unknown
): asserts type is ProvableMaybeHashable {
  assertHasProperty(
    type,
    'toFields',
    'Expected provable type to have a toFields method'
  );
  assertHasProperty(
    type,
    'fromFields',
    'Expected provable type to have a fromFields method'
  );
}

type WithProvable<A> = { provable: A } | A;
type ProvableType<T = any, V = any> = WithProvable<Provable<T, V>>;
type ProvablePureType<T = any, V = any> = WithProvable<ProvablePure<T, V>>;
type ProvableHashableType<T = any, V = any> = WithProvable<
  ProvableHashable<T, V>
>;

type ProvableHashableWide<T = any, V = any, W = any> = Omit<
  ProvableHashable<T, V>,
  'fromValue'
> & {
  fromValue: (value: T | W) => T;
};

type ToProvable<A extends WithProvable<any>> = A extends {
  provable: infer P;
}
  ? P
  : A;

type HashInput = {
  fields?: Field[];
  packed?: [Field, number][];
};
type MaybeHashable<T> = {
  toInput?: (x: T) => HashInput;
  empty?: () => T;
};

type ProvableMaybeHashable<T = any, V = any> = Provable<T, V> &
  MaybeHashable<T>;
type ProvableHashablePure<T = any, V = any> = ProvablePure<T, V> &
  ProvableHashable<T, V>;

/**
 * Pack a value to as few field elements as possible using `toInput()`, falling back to `toFields()` if that's not available.
 *
 * Note: Different than `Packed` in o1js, this uses little-endian packing.
 */
function toFieldsPacked<T>(
  type_: WithProvable<ProvableMaybeHashable<T>>,
  value: T
): Field[] {
  let type = ProvableType.get(type_);
  if (type.toInput === undefined) return type.toFields(value);

  let { fields = [], packed = [] } = toInput(type, value);
  let result = [...fields];
  let current = Field(0);
  let currentSize = 0;

  for (let [field, size] of packed) {
    if (currentSize + size < Field.sizeInBits) {
      current = current.add(field.mul(1n << BigInt(currentSize)));
      currentSize += size;
    } else {
      result.push(current.seal());
      current = field;
      currentSize = size;
    }
  }
  if (currentSize > 0) result.push(current.seal());
  return result;
}

/**
 * Hash a provable value efficiently, by first packing it into as few field elements as possible.
 *
 * Note: Different than `Poseidon.hashPacked()` and `Hashed` (by default) in o1js, this uses little-endian packing.
 */
function hashPacked<T>(
  type: WithProvable<ProvableMaybeHashable<T>>,
  value: T
): Field {
  let fields = toFieldsPacked(type, value);
  return Poseidon.hash(fields);
}

// temporary, until we land `StaticArray`
// this is copied from o1js and then modified: https://github.com/o1-labs/o1js
// License here: https://github.com/o1-labs/o1js/blob/main/LICENSE
function array<A extends NestedProvable>(elementType: A, length: number) {
  type T = InferProvable<A>;
  type V = InferValue<A>;
  let type: ProvableMaybeHashable<T, V> = ProvableType.isProvableType(
    elementType
  )
    ? ProvableType.get(elementType)
    : Struct(elementType);
  return {
    _isArray: true,
    innerType: elementType,
    size: length,

    /**
     * Returns the size of this structure in {@link Field} elements.
     * @returns size of this structure
     */
    sizeInFields() {
      let elementLength = type.sizeInFields();
      return elementLength * length;
    },
    /**
     * Serializes this structure into {@link Field} elements.
     * @returns an array of {@link Field} elements
     */
    toFields(array: T[]) {
      return array.map((e) => type.toFields(e)).flat();
    },
    /**
     * Serializes this structure's auxiliary data.
     * @returns auxiliary data
     */
    toAuxiliary(array?) {
      let array_ = array ?? Array<undefined>(length).fill(undefined);
      return array_?.map((e) => type.toAuxiliary(e));
    },

    /**
     * Deserializes an array of {@link Field} elements into this structure.
     */
    fromFields(fields: Field[], aux?: any[]) {
      let array = [];
      let size = type.sizeInFields();
      let n = length;
      for (let i = 0, offset = 0; i < n; i++, offset += size) {
        array[i] = type.fromFields(
          fields.slice(offset, offset + size),
          aux?.[i]
        );
      }
      return array;
    },
    check(array: T[]) {
      for (let i = 0; i < length; i++) {
        (type as any).check(array[i]);
      }
    },
    toCanonical(x) {
      return x.map((v) => Provable.toCanonical(type, v));
    },

    toValue(x) {
      return x.map((v) => type.toValue(v));
    },

    fromValue(x) {
      return x.map((v) => type.fromValue(v));
    },

    toInput(array) {
      return array.reduce(
        (curr, value) => HashInput.append(curr, toInput(type, value)),
        HashInput.empty
      );
    },

    empty() {
      return Array.from({ length }, () => empty(type));
    },
  } satisfies ProvableHashable<T[], V[]> & {
    _isArray: true;
    innerType: A;
    size: number;
  };
}

// this is copied from o1js and then modified: https://github.com/o1-labs/o1js
// License here: https://github.com/o1-labs/o1js/blob/main/LICENSE
const HashInput = {
  get empty() {
    return {};
  },
  append(input1: HashInput, input2: HashInput): HashInput {
    return {
      fields: (input1.fields ?? []).concat(input2.fields ?? []),
      packed: (input1.packed ?? []).concat(input2.packed ?? []),
    };
  },
};

function toInput<T>(type: ProvableMaybeHashable<T>, value: T): HashInput {
  return type.toInput?.(value) ?? { fields: type.toFields(value) };
}

function empty<T>(type: ProvableMaybeHashable<T>): T {
  return type.empty?.() ?? ProvableType.synthesize(type);
}
