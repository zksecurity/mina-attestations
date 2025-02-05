import { Bool, Bytes, Field, type ProvableHashable, UInt8 } from 'o1js';
import { DynamicArrayBase, provableDynamicArray } from './dynamic-array.ts';
import { ProvableFactory } from '../provable-factory.ts';
import { assert, chunk } from '../util.ts';
import { DynamicSHA2 } from './dynamic-sha2.ts';

export { DynamicBytes };

type DynamicBytes = DynamicBytesBase;

/**
 * Specialization of `DynamicArray` to bytes,
 * with added helper methods to convert instances to/from values.
 *
 * ```ts
 * const Bytes = DynamicBytes({ maxLength: 120 });
 *
 * let bytes = Bytes.fromString('hello');
 * let bytes2 = Bytes.fromBytes([1, 2, 3]);
 *
 * let string = bytes.toString();
 * let uint8array = bytes2.toBytes();
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
      return provableBytes;
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
      return provableBytes.fromValue(
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
  }

  const provableBytes = provableDynamicArray<
    UInt8,
    { value: bigint },
    typeof DynamicBytesBase
  >(UInt8 as any, DynamicBytes).build();

  return DynamicBytes;
}

DynamicBytes.fromBytes = function (bytes: Uint8Array) {
  return DynamicBytes({ maxLength: bytes.length }).fromBytes(bytes);
};

class DynamicBytesBase extends DynamicArrayBase<UInt8, { value: bigint }> {
  get innerType() {
    return UInt8 as any as ProvableHashable<UInt8, { value: bigint }>;
  }

  /**
   * Hash the bytes using variants of SHA2.
   */
  hashToBytes(algorithm: 'sha2-256' | 'sha2-384' | 'sha2-512') {
    switch (algorithm) {
      case 'sha2-256':
        return DynamicSHA2.hash(256, this);
      case 'sha2-384':
        return DynamicSHA2.hash(384, this);
      case 'sha2-512':
        return DynamicSHA2.hash(512, this);
      default:
        assert(false, 'unsupported hash kind');
    }
  }

  /**
   * Convert DynamicBytes to a byte array.
   */
  toBytes() {
    return new Uint8Array(this.toValue().map(({ value }) => Number(value)));
  }

  /**
   * Convert DynamicBytes to a hex string.
   */
  toHex() {
    return [...this.toBytes()]
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Convert DynamicBytes to a string.
   */
  toString() {
    return new TextDecoder().decode(this.toBytes());
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

  valueToJSON(_, value) {
    return value.toHex();
  },

  valueFromJSON(type, value) {
    return type.fromHex(value);
  },
});
