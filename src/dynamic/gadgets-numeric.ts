import {
  Bool,
  Field,
  Int64,
  Provable,
  Sign,
  UInt32,
  UInt64,
  UInt8,
} from 'o1js';
import { assert } from '../util.ts';

export { Numeric, numericMaximumType, type NumericMaximum };

type Numeric = Field | Int64 | UInt64 | UInt32 | UInt8;

// each of these types is naturally included in the next one
const numericTypeOrder = [UInt8, UInt32, UInt64, Int64, Field];

// prettier-ignore
type NumericMaximum<T> = 
  // if we don't know anything about T, we just return `Numeric`
  Numeric extends T ? Numeric :
  // otherwise, return the largest of the types in the union
  Field extends T ? Field :
  Int64 extends T ? Int64 :
  UInt64 extends T ? UInt64 :
  UInt32 extends T ? UInt32 :
  UInt8 extends T ? UInt8 :
  never;

/**
 * Arithmetic and comparison gadgets that work on all pairs of numeric types:
 * Field, Int64, UInt64, UInt32, and UInt8.
 *
 * Example: check if a UInt64 is less than a Field, or compute the sum of a UInt32 and an Int64 (as an Int64).
 *
 * The general strategy is to convert both inputs to the "bigger" type, and then perform the operation there.
 * We also add int64 comparisons which are missing from o1js.
 */
const Numeric = {
  /**
   * Add two numeric values.
   * The returned type is the larger of the two input types, and follows the overflow rules of that type.
   *
   * Example:
   * ```ts
   * const sum: UInt32 = Numeric.add(UInt8.from(5), UInt32.from(10));
   * ```
   */
  add<T extends Numeric, S extends Numeric>(
    left: T,
    right: S
  ): NumericMaximum<T | S> {
    let [a, b] = convertToMaximum(left, right);
    return (a as Numeric).add(b as any) as NumericMaximum<T | S>;
  },

  /**
   * Subtract two numeric values.
   * The returned type is the larger of the two input types, and follows the overflow rules of that type.
   *
   * Example:
   * ```ts
   * const difference: Field = Numeric.subtract(Int64.from(10), Field.from(15));
   * ```
   */
  subtract<T extends Numeric, S extends Numeric>(
    left: T,
    right: S
  ): NumericMaximum<T | S> {
    let [a, b] = convertToMaximum(left, right);
    return (a as Numeric).sub(b as any) as NumericMaximum<T | S>;
  },

  /**
   * Multiply two numeric values.
   * The returned type is the larger of the two input types, and follows the overflow rules of that type.
   */
  multiply<T extends Numeric, S extends Numeric>(
    left: T,
    right: S
  ): NumericMaximum<T | S> {
    let [a, b] = convertToMaximum(left, right);
    return (a as Numeric).mul(b as any) as NumericMaximum<T | S>;
  },

  /**
   * Divide two numeric values.
   * The returned type is the larger of the two input types, and follows the overflow rules of that type.
   */
  divide<T extends Numeric, S extends Numeric>(
    left: T,
    right: S
  ): NumericMaximum<T | S> {
    let [a, b] = convertToMaximum(left, right);
    return (a as Numeric).div(b as any) as NumericMaximum<T | S>;
  },

  /**
   * Compares two numeric values and returns true if `left < right`.
   *
   * **Warning**: when comparing an `Int64` and a `Field`, negative `Int64` are treated as large numbers close to the field size.
   * This is to be consistent with how order of field elements is understood in general.
   */
  lessThan(left: Numeric, right: Numeric): Bool {
    let [a, b] = convertToMaximum(left, right);
    if (a instanceof Int64) {
      return lessThanInt64(a, b as Int64);
    }
    return (a as Field | UInt64 | UInt32 | UInt8).lessThan(b as any);
  },

  /**
   * See {@link Numeric.lessThan}.
   */
  lessThanOrEqual(left: Numeric, right: Numeric): Bool {
    let [a, b] = convertToMaximum(left, right);
    if (a instanceof Int64) {
      return lessThanOrEqualInt64(a, b as Int64);
    }
    return (a as Field | UInt64 | UInt32 | UInt8).lessThanOrEqual(b as any);
  },

  /**
   * See {@link Numeric.lessThan}.
   */
  greaterThan(left: Numeric, right: Numeric): Bool {
    return Numeric.lessThan(right, left);
  },

  /**
   * See {@link Numeric.lessThanOrEqual}.
   */
  greaterThanOrEqual(left: Numeric, right: Numeric): Bool {
    return Numeric.lessThanOrEqual(right, left);
  },
};

type NumericType =
  | typeof Field
  | typeof Int64
  | typeof UInt64
  | typeof UInt32
  | typeof UInt8;

function numericMaximumType(left: unknown, right: unknown): NumericType {
  let leftTypeIndex = numericTypeOrder.findIndex((t) => left === t);
  let rightTypeIndex = numericTypeOrder.findIndex((t) => right === t);
  assert(leftTypeIndex !== -1, 'left is not a numeric type');
  assert(rightTypeIndex !== -1, 'right is not a numeric type');
  return numericTypeOrder[Math.max(leftTypeIndex, rightTypeIndex)]!;
}

function convertToMaximum<T extends Numeric, S extends Numeric>(
  left: T,
  right: S
): [NumericMaximum<T | S>, NumericMaximum<T | S>] {
  const leftTypeIndex = numericTypeOrder.findIndex(
    (type) => left instanceof type
  );
  const rightTypeIndex = numericTypeOrder.findIndex(
    (type) => right instanceof type
  );
  assert(leftTypeIndex !== -1, 'left is not a numeric type');
  assert(rightTypeIndex !== -1, 'right is not a numeric type');
  let leftType = numericTypeOrder[leftTypeIndex];
  let rightType = numericTypeOrder[rightTypeIndex];

  let resultType = numericTypeOrder[Math.max(leftTypeIndex, rightTypeIndex)]!;

  let leftConverted =
    leftTypeIndex < rightTypeIndex
      ? resultType === Field
        ? leftType === Int64
          ? (left as Int64).toField()
          : (leftType as typeof UInt64 | typeof UInt32 | typeof UInt8).toFields(
              left as UInt64 | UInt32 | UInt8
            )[0]!
        : resultType === Int64
        ? leftType === UInt64
          ? Int64.fromUnsigned(left as UInt64)
          : Int64.fromUnsigned((left as UInt32 | UInt8).toUInt64())
        : resultType === UInt64
        ? (left as UInt32 | UInt8).toUInt64()
        : (left as UInt8).toUInt32()
      : left;

  let rightConverted =
    leftTypeIndex > rightTypeIndex
      ? resultType === Field
        ? rightType === Int64
          ? (right as Int64).toField()
          : (
              rightType as typeof UInt64 | typeof UInt32 | typeof UInt8
            ).toFields(right as UInt64 | UInt32 | UInt8)[0]!
        : resultType === Int64
        ? rightType === UInt64
          ? Int64.fromUnsigned(right as UInt64)
          : Int64.fromUnsigned((right as UInt32 | UInt8).toUInt64())
        : resultType === UInt64
        ? (right as UInt32 | UInt8).toUInt64()
        : (right as UInt8).toUInt32()
      : right;

  return [leftConverted, rightConverted] as [
    NumericMaximum<T | S>,
    NumericMaximum<T | S>
  ];
}

// Int64 comparisons

function lessThanInt64(left: Int64, right: Int64): Bool {
  let magnitudeLessThan = left.magnitude.lessThan(right.magnitude);
  let magnitudeEqual = left.magnitude.equals(right.magnitude);
  let magnitudeGreaterThan = magnitudeLessThan.not().and(magnitudeEqual.not());
  let unequalSign = left.sgn.mul(right.sgn).equals(Sign.minusOne);
  let leftNegative = left.sgn.equals(Sign.minusOne);
  return Provable.if(
    unequalSign,
    // if the signs are unequal, left < right <=> left < 0
    // (this works because sign == -1 guarantees magnitude != 0)
    leftNegative,
    // if the signs are equal, and
    // negative: left < right <=> left.magnitude > right.magnitude
    // positive: left < right <=> left.magnitude < right.magnitude
    Provable.if(leftNegative, magnitudeGreaterThan, magnitudeLessThan)
  );
}

function lessThanOrEqualInt64(left: Int64, right: Int64): Bool {
  let magnitudeLessThanOrEqual = left.magnitude.lessThanOrEqual(
    right.magnitude
  );
  let magnitudeEqual = left.magnitude.equals(right.magnitude);
  let magnitudeGreaterThanOrEqual = magnitudeLessThanOrEqual
    .not()
    .or(magnitudeEqual);
  let unequalSign = left.sgn.mul(right.sgn).equals(Sign.minusOne);
  let leftNegative = left.sgn.equals(Sign.minusOne);
  return Provable.if(
    unequalSign,
    // if the signs are unequal, left <= right <=> left < 0
    leftNegative,
    // if the signs are equal, and
    // negative: left <= right <=> left.magnitude >= right.magnitude
    // positive: left <= right <=> left.magnitude <= right.magnitude
    Provable.if(
      leftNegative,
      magnitudeGreaterThanOrEqual,
      magnitudeLessThanOrEqual
    )
  );
}
