import { Bool, Field, Provable, UInt8 } from 'o1js';
import { DynamicArrayBase, provableDynamicArray } from './dynamic-array.ts';
import { ProvableFactory } from '../provable-factory.ts';
import { assert } from '../util.ts';
import { mapValue } from '../o1js-missing.ts';

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
      return provableArray;
    }

    /**
     * Create DynamicBytes from a string.
     */
    static from(s: string) {
      return provableArray.fromValue(s);
    }
  }

  const provableArray = mapValue(
    provableDynamicArray<UInt8, { value: bigint }, typeof DynamicStringBase>(
      UInt8 as any,
      DynamicString
    ),
    (s): string =>
      new TextDecoder().decode(
        new Uint8Array(s.map(({ value }) => Number(value)))
      ),
    (s) => {
      if (s instanceof DynamicStringBase) return s;
      return [...new TextEncoder().encode(s)].map((t) =>
        UInt8.toValue(UInt8.from(t))
      );
    }
  );

  return DynamicString;
}

class DynamicStringBase extends DynamicArrayBase<UInt8, { value: bigint }> {
  get innerType() {
    return UInt8 as any as Provable<UInt8, { value: bigint }>;
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
