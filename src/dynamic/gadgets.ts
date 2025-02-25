/**
 * Misc gadgets for attestation contracts.
 */
import {
  Bool,
  Field,
  Gadgets,
  Int64,
  Provable,
  Sign,
  TupleN,
  UInt32,
  UInt64,
  UInt8,
} from 'o1js';
import { assert } from '../util.ts';

export {
  pack,
  unpack,
  packBytes,
  unpackBytes,
  uint64FromBytesBE,
  uint64ToBytesBE,
  unsafeIf,
  seal,
  lessThan16,
  assertInRange16,
  assertLessThan16,
  rangeCheck,
  lessThanInt64,
  lessThanOrEqualInt64,
};

/**
 * Pack a list of fields of bit size `chunkSize` each into a single field.
 * Uses little-endian encoding.
 *
 * **Warning**: Assumes, but doesn't prove, that each chunk fits in the chunk size.
 */
function pack(chunks: Field[], chunkSize: number): Field {
  let p = chunks.length * chunkSize;
  assert(
    chunks.length <= 1 || p < Field.sizeInBits,
    () => `pack(): too many chunks, got ${chunks.length} * ${chunkSize} = ${p}`
  );
  let sum = Field(0);
  chunks.forEach((chunk, i) => {
    sum = sum.add(chunk.mul(1n << BigInt(i * chunkSize)));
  });
  return sum.seal();
}

/**
 * Unpack a field into a list of fields of bit size `chunkSize` each.
 * Uses little-endian encoding.
 *
 * Proves that the output fields have at most `chunkSize` bits,
 * and that the input has at most `chunkSize * numChunks` bits.
 */
function unpack<N extends number>(
  word: Field | bigint,
  chunkSize: 1 | 4 | 8 | 16 | 32 | 64,
  numChunks: N
) {
  function computeChunks() {
    let x = Field.from(word).toBigInt();
    let mask = (1n << BigInt(chunkSize)) - 1n;
    return TupleN.fromArray(
      numChunks,
      Array.from({ length: numChunks }, (_, i) =>
        Field((x >> BigInt(i * chunkSize)) & mask)
      )
    );
  }
  let chunks = Field.from(word).isConstant()
    ? computeChunks()
    : Provable.witnessFields(numChunks, computeChunks);

  // range check fields, so decomposition is unique and outputs are in range
  chunks.forEach((chunk) => rangeCheck(chunk, chunkSize));

  // check decomposition
  // this asserts that the composition doesn't overflow
  pack(chunks, chunkSize).assertEquals(word);

  return chunks;
}

function packBytes(bytes: UInt8[]) {
  let fields = bytes.map((x) => x.value);
  return pack(fields, 8);
}

function unpackBytes(word: Field, numBytes: number) {
  let fields = unpack(word, 8, numBytes);
  return fields.map((x) => UInt8.Unsafe.fromField(x));
}

function uint64FromBytesBE(bytes: UInt8[]) {
  let field = packBytes(bytes.toReversed());
  return UInt64.Unsafe.fromField(field);
}
function uint64ToBytesBE(x: UInt64) {
  return unpackBytes(x.value, 8).toReversed();
}

function rangeCheck(x: Field, bits: 1 | 4 | 8 | 16 | 32 | 64) {
  switch (bits) {
    case 1:
      x.assertBool();
      break;
    case 4:
      rangeCheckLessThan16(4, x);
    case 8:
      Gadgets.rangeCheck8(x);
      break;
    case 16:
      Gadgets.rangeCheck16(x);
      break;
    case 32:
      Gadgets.rangeCheck32(x);
      break;
    case 64:
      UInt64.check(UInt64.Unsafe.fromField(x));
      break;
  }
}

/**
 * Slightly more efficient version of Provable.if() which produces garbage if both t is a non-dummy and b is true.
 *
 * t + b*s
 *
 * Cost: 2*|T|, or |T| if t is all zeros
 */
function unsafeIf<T>(b: Bool, type: Provable<T>, t: T, s: T): T {
  let fields = add(type.toFields(t), mul(type.toFields(s), b));
  let aux = type.toAuxiliary(t);
  Provable.asProver(() => {
    if (b.toBoolean()) aux = type.toAuxiliary(s);
  });
  return type.fromFields(fields, aux);
}

function seal<T>(type: Provable<T>, t: T): T {
  let fields = type.toFields(t);
  let aux = type.toAuxiliary(t);
  fields = fields.map((x) => x.seal());
  return type.fromFields(fields, aux);
}

function mul(fields: Field[], mask: Bool) {
  return fields.map((x) => x.mul(mask.toField()));
}
function add(t: Field[], s: Field[]) {
  return t.map((t, i) => t.add(s[i]!));
}

/**
 * Asserts that 0 <= i <= x without other assumptions on i,
 * assuming that 0 <= x < 2^16.
 */
function assertInRange16(i: Field, x: Field | number) {
  Gadgets.rangeCheck16(i);
  Gadgets.rangeCheck16(Field(x).sub(i).seal());
}

/**
 * Asserts that i < x, assuming that i in [0,2^32) and x in [0,2^16).
 *
 * Cost: 1.5
 */
function assertLessThan16(i: UInt32, x: Field | number) {
  if (i.isConstant() && Field(x).isConstant()) {
    assert(i.toBigint() < Field(x).toBigInt(), 'assertLessThan16');
  }
  // assumptions on i, x imply that x - 1 - i is in [0, 2^16) - 1 - [0, 2^32) = [-1-2^32, 2^16-1) = (p-2^32, p) u [0, 2^16-1)
  // checking 0 <= x - 1 - i < 2^16 excludes the negative part of the range
  Gadgets.rangeCheck16(Field(x).sub(1).sub(i.value).seal());
}

/**
 * Returns i <? x for i, x < 2^16.
 *
 * Note: This is also sound for i < 2^32, just not complete in that case
 *
 * Cost: 2.5
 */
function lessThan16(i: Field, x: Field | number): Bool {
  let b = Provable.witness(Field, () =>
    BigInt(i.toBigInt() < Field(x).toBigInt())
  );
  let isLessThan = b.assertBool();
  Gadgets.rangeCheck16(
    b
      .mul(1n << 16n)
      .add(i)
      .sub(x)
  );
  return isLessThan;
}

// copied from o1js
// https://github.com/o1-labs/o1js/blob/main/src/lib/provable/gadgets/range-check.ts
function rangeCheckLessThan16(bits: number, x: Field) {
  assert(bits < 16, `bits must be less than 16, got ${bits}`);

  if (x.isConstant()) {
    assert(
      x.toBigInt() < 1n << BigInt(bits),
      `rangeCheckLessThan16: expected field to fit in ${bits} bits, got ${x}`
    );
    return;
  }

  // check that x fits in 16 bits
  Gadgets.rangeCheck16(x);

  // check that 2^(16 - bits)*x < 2^16, i.e. x < 2^bits
  let xM = x.mul(1 << (16 - bits)).seal();
  Gadgets.rangeCheck16(xM);
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
