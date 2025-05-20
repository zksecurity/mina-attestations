/**
 * A dynamic record is a key-value list which can contain keys/values you are not aware of at compile time.
 */
import {
  Field,
  type From,
  type InferProvable,
  Option,
  Poseidon,
  Provable,
  type ProvableHashable,
  Struct,
  Unconstrained,
} from 'o1js';
import {
  array,
  ProvableType,
  type ProvableHashableType,
} from '../o1js-missing.ts';
import { TypeBuilder } from '../provable-type-builder.ts';
import {
  assertExtendsShape,
  assertHasProperty,
  mapObject,
  pad,
  zipObjects,
} from '../util.ts';
import { NestedProvable } from '../nested.ts';
import { ProvableFactory } from '../provable-factory.ts';
import {
  deserializeNestedProvable,
  deserializeNestedProvableValue,
  serializeNestedProvableType,
  serializeNestedProvableValue,
} from '../serialize-provable.ts';
import { hashString, packToField } from './dynamic-hash.ts';
import { BaseType } from './dynamic-base-types.ts';
import { z } from 'zod';
import { SerializedTypeSchema, SerializedValueSchema } from '../validation.ts';

export {
  DynamicRecord,
  GenericRecord,
  type UnknownRecord,
  type DynamicRecordClass,
  extractProperty,
};

type DynamicRecord<TKnown = any> = DynamicRecordBase<TKnown>;

type DynamicRecordClass<AKnown extends Record<string, any>> = ReturnType<
  typeof DynamicRecord<AKnown>
>;

function DynamicRecord<
  AKnown extends Record<string, ProvableHashableType>,
  TKnown extends { [K in keyof AKnown]: InferProvable<AKnown[K]> } = {
    [K in keyof AKnown]: InferProvable<AKnown[K]>;
  }
>(knownShape: AKnown, { maxEntries }: { maxEntries: number }) {
  let shape = mapObject<
    AKnown,
    { [K in keyof TKnown]: ProvableHashableType<TKnown[K]> }
  >(knownShape, (type) => type);

  const emptyTKnown: TKnown = mapObject(shape, (type) =>
    ProvableType.get(type).empty()
  );

  return class DynamicRecord extends DynamicRecordBase<TKnown> {
    // accepted type is From<> for the known subfields and unchanged for the unknown ones
    static from<T extends From<AKnown> & UnknownRecord>(
      value: T
    ): DynamicRecordBase<TKnown> {
      return DynamicRecord.provable.fromValue(value);
    }

    static fromShape<A extends AKnown>(
      type: A,
      value: { [K in keyof A]: From<A[K]> }
    ): DynamicRecordBase<TKnown> {
      let actual: { [K in keyof A]: InferProvable<A[K]> } = mapObject(
        zipObjects(type, value),
        ([type, value]) => ProvableType.get(type).fromValue(value)
      );
      return DynamicRecord.provable.fromValue(actual);
    }

    static get shape(): {
      [K in keyof TKnown]: ProvableHashableType<TKnown[K]>;
    } {
      return shape;
    }

    static provable = TypeBuilder.shape({
      entries: array(Option(Struct({ key: Field, value: Field })), maxEntries),
      actual: Unconstrained.withEmpty<UnknownRecord>(emptyTKnown),
    })
      .forClass<DynamicRecordBase<TKnown>>(DynamicRecord)
      .mapValue<UnknownRecord>({
        there({ actual }) {
          return actual;
        },
        back(actual) {
          // validate that `actual` (at least) contains all known keys
          assertExtendsShape(actual, knownShape);

          let entries = Object.entries<unknown>(actual).map(([key, value]) => {
            let type =
              key in knownShape
                ? NestedProvable.get(knownShape[key]!)
                : undefined;
            let actualValue =
              type === undefined ? value : type.fromValue(value);
            return {
              key: hashString(key).toBigInt(),
              value: packToField(actualValue, type).toBigInt(),
            };
          });
          return { entries: pad(entries, maxEntries, undefined), actual };
        },
        distinguish(x) {
          return x instanceof DynamicRecordBase;
        },
      })
      .build();

    get maxEntries() {
      return maxEntries;
    }
    get knownShape() {
      return shape;
    }
  };
}

const OptionField = Option(Field);
const OptionKeyValue = Option(Struct({ key: Field, value: Field }));

type GenericRecord = GenericRecordBase;

function GenericRecord({ maxEntries }: { maxEntries: number }) {
  // TODO provable
  return class GenericRecord extends GenericRecordBase {
    get maxEntries() {
      return maxEntries;
    }
  };
}

class GenericRecordBase {
  entries: Option<{ key: Field; value: Field }>[];
  actual: Unconstrained<UnknownRecord>;

  constructor(value: DynamicRecordRaw) {
    this.entries = value.entries;
    this.actual = value.actual;
  }

  get maxEntries(): number {
    throw Error('Need subclass');
  }
  get knownShape() {
    return {};
  }

  static from(actual: UnknownRecord): GenericRecordBase {
    let entries = Object.entries(actual).map(([key, value]) => {
      return OptionKeyValue.from({
        key: hashString(key),
        value: packToField(value),
      });
    });
    let maxEntries = this.prototype.maxEntries;
    let padded = pad(entries, maxEntries, OptionKeyValue.none());
    return new this({ entries: padded, actual: Unconstrained.from(actual) });
  }

  getAny<A extends ProvableHashableType>(valueType: A, key: string) {
    // find valueHash for key
    let keyHash = hashString(key);
    let current = OptionField.none();

    for (let { isSome, value: entry } of this.entries) {
      let isCurrentKey = isSome.and(entry.key.equals(keyHash));
      current.isSome = current.isSome.or(isCurrentKey);
      current.value = Provable.if(isCurrentKey, entry.value, current.value);
    }
    let valueHash = current.assertSome(`Key not found: "${key}"`);

    // witness actual value for key
    let value = Provable.witness(
      valueType,
      () => this.actual.get()[key] as any
    );

    // assert that value matches hash, and return it
    packToField(value, valueType).assertEquals(
      valueHash,
      `Bug: Invalid value for key "${key}"`
    );

    return value;
  }

  hash(): Field {
    // hash one entry at a time, ignoring dummy entries
    let state = Poseidon.initialState();

    for (let { isSome, value: entry } of this.entries) {
      let { key, value } = entry;
      let newState = Poseidon.update(state, [key, value]);
      state[0] = Provable.if(isSome, newState[0], state[0]);
      state[1] = Provable.if(isSome, newState[1], state[1]);
      state[2] = Provable.if(isSome, newState[2], state[2]);
    }

    return state[0];
  }
}

BaseType.GenericRecord = GenericRecord;
GenericRecord.Base = GenericRecordBase;

class DynamicRecordBase<TKnown = any> extends GenericRecordBase {
  get knownShape(): { [K in keyof TKnown]: ProvableHashableType<TKnown[K]> } {
    throw Error('Need subclass');
  }

  get<K extends keyof TKnown & string>(key: K): TKnown[K] {
    let valueType: ProvableHashable<TKnown[K]> = ProvableType.get(
      this.knownShape[key]
    );
    return this.getAny(valueType, key);
  }
}

BaseType.DynamicRecord = DynamicRecord;
DynamicRecord.Base = DynamicRecordBase;

type DynamicRecordRaw = {
  entries: Option<{ key: Field; value: Field }>[];
  actual: Unconstrained<UnknownRecord>;
};

type UnknownRecord = Record<string, unknown>;

// compatible key extraction

function extractProperty(data: unknown, key: string): unknown {
  if (data instanceof DynamicRecord.Base) return data.get(key);
  assertHasProperty(data, key, `Key not found: "${key}"`);
  return data[key];
}

// serialize/deserialize

ProvableFactory.register('DynamicRecord', DynamicRecord, {
  typeSchema: z.object({
    maxEntries: z.number(),
    knownShape: z.record(SerializedTypeSchema),
  }),
  valueSchema: z.record(SerializedValueSchema),

  typeToJSON(constructor) {
    return {
      maxEntries: constructor.prototype.maxEntries,
      knownShape: serializeNestedProvableType(constructor.prototype.knownShape),
    };
  },

  typeFromJSON(json) {
    let { maxEntries, knownShape } = json;
    let shape = deserializeNestedProvable(knownShape);
    return DynamicRecord(shape as any, { maxEntries });
  },

  valueToJSON(type, value) {
    let actual = type.provable.toValue(value);
    return serializeNestedProvableValue(actual);
  },

  valueFromJSON(type, value) {
    let actual = deserializeNestedProvableValue(value);
    return type.provable.fromValue(actual);
  },
});
