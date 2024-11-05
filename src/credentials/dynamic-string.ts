import { Bool, Field, type ProvableHashable, UInt8 } from 'o1js';
import { DynamicArrayBase, provableDynamicArray } from './dynamic-array.ts';
import { ProvableFactory } from '../provable-factory.ts';
import { assert } from '../util.ts';

export { DynamicString };

type DynamicString = DynamicStringBase;

/**
 * Specialization of `DynamicArray` to string (represented as array of bytes),
 * with added helper methods to create instances.
 *
 * ```ts
 * const String = DynamicString({ maxLength: 120 });
 *
 * let string = String.from('hello');
 * ```
 */
function DynamicString({ maxLength }: { maxLength: number }) {
  // assert maxLength bounds
  assert(maxLength >= 0, 'maxLength must be >= 0');
  assert(maxLength < 2 ** 16, 'maxLength must be < 2^16');

  class DynamicString extends DynamicStringBase {
    static get maxLength() {
      return maxLength;
    }
    static get provable() {
      return provableString;
    }

    /**
     * Create DynamicBytes from a string.
     */
    static from(s: string) {
      return provableString.fromValue(s);
    }
  }

  const provableString = provableDynamicArray<
    UInt8,
    { value: bigint },
    typeof DynamicStringBase
  >(UInt8 as any, DynamicString)
    .mapValue<string>({
      there(s) {
        return dec.decode(Uint8Array.from(s, ({ value }) => Number(value)));
      },
      backAndDistinguish(s) {
        // gracefully handle different maxLength
        if (s instanceof DynamicStringBase) {
          if (s.maxLength === maxLength) return s;
          s = s.toString();
        }
        return [...enc.encode(s)].map((t) => ({ value: BigInt(t) }));
      },
    })
    .build();

  return DynamicString;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

class DynamicStringBase extends DynamicArrayBase<UInt8, { value: bigint }> {
  get innerType() {
    return UInt8 as any as ProvableHashable<UInt8, { value: bigint }>;
  }

  /**
   * Convert DynamicBytes to a string.
   */
  toString() {
    return this.toValue() as any as string;
  }
}

DynamicString.Base = DynamicStringBase;

// serialize/deserialize

ProvableFactory.register(DynamicString, {
  typeToJSON(constructor) {
    return { maxLength: constructor.maxLength };
  },

  typeFromJSON(json) {
    return DynamicString({ maxLength: json.maxLength });
  },

  valueToJSON(_, value) {
    return value.toString();
  },

  valueFromJSON(type, value) {
    return type.from(value);
  },
});
