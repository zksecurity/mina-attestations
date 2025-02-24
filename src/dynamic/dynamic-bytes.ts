import { Bytes, Field, type ProvableHashable, UInt8 } from 'o1js';
import {
  DynamicArray,
  DynamicArrayBase,
  provableDynamicArray,
} from './dynamic-array.ts';
import { ProvableFactory } from '../provable-factory.ts';
import { assert, chunk, stringLength } from '../util.ts';
import { DynamicSHA2 } from './dynamic-sha2.ts';
import type { ProvableHashablePure } from '../o1js-missing.ts';

export { DynamicBytes, DynamicBytesBase };

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
function DynamicBytes({
  maxLength,
}: {
  maxLength: number;
}): typeof DynamicBytesBase & {
  /**
   * Create DynamicBytes from a byte array in various forms.
   *
   * ```ts
   * let bytes = Bytes.fromBytes([1, 2, 3]);
   * ```
   */
  fromBytes(
    bytes: Uint8Array | (number | bigint | UInt8)[] | Bytes
  ): DynamicBytes;

  /**
   * Create DynamicBytes from a hex string.
   *
   * ```ts
   * let bytes = Bytes.fromHex('010203');
   * ```
   */
  fromHex(hex: string): DynamicBytes;

  /**
   * Create DynamicBytes from a string.
   */
  fromString(s: string): DynamicBytes;

  provable: ProvableHashablePure<DynamicBytes, Uint8Array>;
} {
  // assert maxLength bounds
  assert(maxLength >= 0, 'maxLength must be >= 0');
  assert(maxLength < 2 ** 16, 'maxLength must be < 2^16');

  class DynamicBytes_ extends DynamicBytesBase {
    static get maxLength() {
      return maxLength;
    }
    static get provable() {
      return provableBytes;
    }

    static fromBytes(bytes: Uint8Array | (number | UInt8)[] | Bytes) {
      if (bytes instanceof Uint8Array) return provableBytes.fromValue(bytes);
      if (bytes instanceof Bytes.Base) bytes = bytes.bytes;
      return new DynamicBytes_(
        bytes.map((t) => UInt8.from(t)),
        Field(bytes.length)
      );
    }

    static fromHex(hex: string) {
      assert(hex.length % 2 === 0, 'Hex string must have even length');
      let bytes = chunk([...hex], 2).map((s) => parseInt(s.join(''), 16));
      return DynamicBytes_.fromBytes(bytes);
    }

    static fromString(s: string) {
      return DynamicBytes_.fromBytes(new TextEncoder().encode(s));
    }
  }

  const provableBytes = provableDynamicArray<
    UInt8,
    { value: bigint },
    typeof DynamicBytesBase
  >(UInt8 as any, DynamicBytes_)
    .mapValue<Uint8Array>({
      there(s) {
        return Uint8Array.from(s, ({ value }) => Number(value));
      },
      backAndDistinguish(s) {
        // gracefully handle different maxLength
        if (s instanceof DynamicBytesBase) {
          if (s.maxLength === maxLength) return s;
          if (s.maxLength < maxLength) return s.growMaxLengthTo(maxLength);
          // shrinking max length will only work outside circuit
          s = s.toBytes();
        }
        return [...s].map((t) => ({ value: BigInt(t) }));
      },
    })
    .build();

  return DynamicBytes_;
}

DynamicBytes.fromBytes = function (bytes: Uint8Array) {
  return DynamicBytes({ maxLength: bytes.length }).fromBytes(bytes);
};

DynamicBytes.from = function (
  input: DynamicArray<UInt8> | Uint8Array | string | (number | UInt8)[]
): DynamicBytes {
  if (typeof input === 'string') {
    let Bytes = DynamicBytes({ maxLength: stringLength(input) });
    return Bytes.fromString(input);
  }
  if (input instanceof Uint8Array || Array.isArray(input)) {
    let Bytes = DynamicBytes({ maxLength: input.length });
    return Bytes.fromBytes(input);
  }
  assert(input instanceof DynamicArray.Base, 'invalid input');
  if (input instanceof DynamicBytesBase) return input;

  // if this is not a DynamicBytes, we construct an equivalent one
  let Bytes = DynamicBytes({ maxLength: input.maxLength });
  let bytes = new Bytes(input.array, input.length);
  bytes._indexMasks = input._indexMasks;
  bytes.__dummyMask = input.__dummyMask;
  bytes._indicesInRange = input._indicesInRange;
  return bytes;
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
    return this.toValue() as any as Uint8Array;
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

  growMaxLengthTo(maxLength: number): DynamicBytes {
    return DynamicBytes.from(super.growMaxLengthTo(maxLength));
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
