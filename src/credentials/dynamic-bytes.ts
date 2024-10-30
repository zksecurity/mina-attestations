import { Bool, Bytes, Field, Provable, UInt8 } from 'o1js';
import { DynamicArrayBase, provableDynamicArray } from './dynamic-array.ts';
import { ProvableFactory } from '../provable-factory.ts';
import { assert, chunk } from '../util.ts';

export { DynamicBytes };

/**
 * Specialization of `DynamicArray` to bytes,
 * with added helper methods to create instances.
 *
 * ```ts
 * const Bytes = DynamicBytes({ maxLength: 120 });
 *
 * let bytes = Bytes.fromString('hello');
 * let bytes2 = Bytes.fromBytes([1, 2, 3]);
 * ```
 */
function DynamicBytes({ maxLength }: { maxLength: number }) {
  // assert maxLength bounds
  assert(maxLength >= 0, 'maxLength must be >= 0');
  assert(maxLength < 2 ** 16, 'maxLength must be < 2^16');

  class DynamicBytes extends DynamicBytesBase {
    static get maxLength() {
      return maxLength;
    }
    static get provable() {
      return provableArray;
    }

    /**
     * Create DynamicBytes from a byte array in various forms.
     *
     * ```ts
     * let bytes = Bytes.fromBytes([1, 2, 3]);
     * ```
     */
    static fromBytes(bytes: Uint8Array | (number | bigint | UInt8)[] | Bytes) {
      if (bytes instanceof Bytes.Base) bytes = bytes.bytes;
      return provableArray.fromValue(
        [...bytes].map((t) => UInt8.from(t)) as any
      );
    }

    /**
     * Create DynamicBytes from a hex string.
     *
     * ```ts
     * let bytes = Bytes.fromHex('010203');
     * ```
     */
    static fromHex(hex: string) {
      assert(hex.length % 2 === 0, 'Hex string must have even length');
      let bytes = chunk([...hex], 2).map((s) => parseInt(s.join(''), 16));
      return DynamicBytes.fromBytes(bytes);
    }

    /**
     * Create DynamicBytes from a string.
     */
    static fromString(s: string) {
      return DynamicBytes.fromBytes(new TextEncoder().encode(s));
    }

    /**
     * Convert DynamicBytes to a byte array.
     */
    static toBytes(bytes: DynamicBytes) {
      return new Uint8Array(bytes.toValue().map(({ value }) => Number(value)));
    }

    /**
     * Convert DynamicBytes to a hex string.
     */
    static toHex(bytes: DynamicBytes) {
      return [...DynamicBytes.toBytes(bytes)]
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
    }

    /**
     * Convert DynamicBytes to a string.
     */
    static toString(bytes: DynamicBytes) {
      return new TextDecoder().decode(DynamicBytes.toBytes(bytes));
    }
  }

  const provableArray = provableDynamicArray<UInt8, { value: bigint }>(
    UInt8 as any,
    DynamicBytes
  );

  return DynamicBytes;
}

class DynamicBytesBase extends DynamicArrayBase<UInt8, { value: bigint }> {
  get innerType() {
    return UInt8 as any as Provable<UInt8, { value: bigint }>;
  }
}

DynamicBytes.Base = DynamicBytesBase;

// serialize/deserialize

ProvableFactory.register(DynamicBytes, {
  typeToJSON(constructor) {
    return { maxLength: constructor.maxLength };
  },

  typeFromJSON(json) {
    return DynamicBytes({ maxLength: json.maxLength });
  },

  valueToJSON(type, value) {
    return type.toHex(value);
  },

  valueFromJSON(type, value) {
    return type.fromHex(value);
  },
});
