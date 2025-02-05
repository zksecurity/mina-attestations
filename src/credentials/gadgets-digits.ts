/**
 * Gadgets to convert any field element to/from digits in some base.
 */
import { Field, Provable, UInt8 } from 'o1js';
import { DynamicArray } from './dynamic-array.ts';
import { assertInRange16 } from './gadgets.ts';
import { assert } from '../util.ts';
import { DynamicString } from './dynamic-string.ts';

export { toDecimalString, toBaseBE, fromBaseBE };

/**
 * Computes the unique decimal string representation of `value`.
 *
 * You need to pass in the maximum supported number of digits `maxDigits`.
 *
 * The method costs about `10 * maxDigits` constraints.
 */
function toDecimalString(value: Field, maxDigits: number): DynamicString {
  let digits = toBaseBE(value, 10, maxDigits);

  // map the digits to ASCII characters
  let asciiDigits = digits.map(UInt8, (digit) =>
    UInt8.Unsafe.fromField(digit.add(48n).seal())
  );
  return DynamicString.from(asciiDigits);
}

/**
 * Computes a variable-length digit representation of `value` in base `base`.
 *
 * Returns a `DynamicArray` that starts with the **most significant digit**.
 *
 * The method guarantees that:
 * - The most significant digit is non-zero (unless the value is zero)
 * - The dynamic length of the array equals the minimum number of digits needed to represent the value.
 * - The output digits are in the range `[0, base)`.
 *
 * You need to pass in the maximum supported number of digits `maxDigits`, and the cost
 * in terms of constraints linearly depends on this value.
 */
function toBaseBE(
  value: Field,
  base: number,
  maxDigits: number
): DynamicArray<Field, bigint> {
  let digits = Provable.witness(
    DynamicArray(Field, { maxLength: maxDigits }),
    () => {
      let basen = BigInt(base);
      let remaining = value.toBigInt();
      let digitsLE: bigint[] = [];
      while (remaining > 0) {
        digitsLE.push(remaining % basen);
        remaining /= basen;
      }
      return digitsLE.reverse();
    }
  );
  // all digits are in range
  digits.array.forEach((d) => assertDigit(d, base));

  // the digits correctly represent the value
  fromBaseBE(digits, base).assertEquals(value);

  // the most significant digit is not 0, except if the value is 0
  if (maxDigits > 0) {
    digits.array[0]!.equals(0)
      .implies(value.equals(0))
      .assertTrue('most significant digit must not be 0');
  }
  return digits;
}

/**
 * Recomputes the value from a variable-length digit representation in base `base`.
 *
 * Expects a `DynamicArray` that contains digits in big-endian order.
 *
 * Digits are _assumed_ (not proved) to be in the range `[0, base)` or a similarly
 * "small" range that guarantees that the digit sum doesn't wrap around the field.
 */
function fromBaseBE(digits: DynamicArray<Field>, base: number): Field {
  // this gadget is only sound if the digit sum can't overflow
  assert(
    BigInt(base) ** BigInt(digits.maxLength) < Field.ORDER,
    'base^maxLength must not overflow the field'
  );

  // compute powers to multiply digits with
  // base^3, base^2, base^1, base^0, 0, 0, ..., 0
  //                                 ^ length
  let power = Field(1);
  let powers: Field[] = Array(digits.maxLength);
  digits.forEachReverse((_, isPadding, i) => {
    powers[i] = Provable.if(isPadding.not(), power, Field(0));
    if (i > 0) power = Provable.if(isPadding.not(), power.mul(base), power);
  });

  let sum = Field(0);
  digits.forEach((digit, _, i) => {
    sum = sum.add(digit.mul(powers[i]!));
  });
  return sum.seal();
}

function assertDigit(digit: Field, base: number) {
  if (base === 2) {
    digit.assertBool();
    return;
  }
  assert(base < 2 ** 16, 'base must be < 2^16');
  assertInRange16(digit, base - 1);
}
