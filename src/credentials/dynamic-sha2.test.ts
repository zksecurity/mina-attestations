import { Bytes, Provable, UInt32, UInt64 } from 'o1js';
import { deepStrictEqual } from 'node:assert';
import { DynamicSHA2 } from './dynamic-sha2.ts';
import { stringLength, zip } from '../util.ts';
import { DynamicBytes } from './dynamic-bytes.ts';
import test from 'node:test';
import { SHA2 } from './sha2.ts';
import { DynamicString } from './dynamic-string.ts';

const DynBytes = DynamicBytes({ maxLength: 430 });
const StaticBytes = Bytes(stringLength(longString()));

let bytes = DynBytes.fromString(longString());
let staticBytes = StaticBytes.fromString(longString());

await test('padding 256', () => {
  let actualPadding = DynamicSHA2.padding256(bytes);
  let expectedPadding = SHA2.padding256(staticBytes);
  deepStrictEqual(
    actualPadding.toValue().map(blockToHexBytes),
    expectedPadding.map(blockToHexBytes)
  );
});

await test('padding 512', () => {
  let actualPadding = DynamicSHA2.padding512(bytes);
  let expectedPadding = SHA2.padding512(staticBytes);

  deepStrictEqual(
    actualPadding.toValue().map(blockToHexBytes64),
    expectedPadding.map(blockToHexBytes64)
  );
});

const expectedHash256 = await sha2(256, longString());
const expectedHash384 = await sha2(384, longString());
const expectedHash512 = await sha2(512, longString());

await test('sha256 outside circuit', async () => {
  deepStrictEqual(
    DynamicSHA2.hash(256, bytes).toBytes(),
    expectedHash256.toBytes()
  );

  deepStrictEqual(
    SHA2.hash(256, staticBytes).toBytes(),
    expectedHash256.toBytes()
  );

  // also works with DynamicString and DynamicBytes

  let String = DynamicString({ maxLength: 20 });
  let string = String.from('hello');
  deepStrictEqual(
    string.hashToBytes('sha2-256').toHex(),
    (await sha2(256, 'hello')).toHex()
  );

  let Bytes = DynamicBytes({ maxLength: 20 });
  let bytes_ = Bytes.fromString('hello again!');
  deepStrictEqual(
    bytes_.hashToBytes('sha2-256').toHex(),
    (await sha2(256, 'hello again!')).toHex()
  );
});

await test('sha384 outside circuit', () => {
  deepStrictEqual(
    DynamicSHA2.hash(384, bytes).toBytes(),
    expectedHash384.toBytes()
  );

  deepStrictEqual(
    SHA2.hash(384, staticBytes).toBytes(),
    expectedHash384.toBytes()
  );
});

await test('sha512 outside circuit', () => {
  deepStrictEqual(
    DynamicSHA2.hash(512, bytes).toBytes(),
    expectedHash512.toBytes()
  );

  deepStrictEqual(
    SHA2.hash(512, staticBytes).toBytes(),
    expectedHash512.toBytes()
  );
});

// in-circuit test

async function circuit(len: 256 | 384 | 512) {
  let bytesVar = Provable.witness(DynBytes, () => bytes);
  let hash = DynamicSHA2.hash(len, bytesVar);

  zip(hash.bytes, (await sha2(len, longString())).bytes).forEach(
    ([a, b], i) => {
      a.assertEquals(b, `hash[${i}]`);
    }
  );
}

async function circuitStatic(len: 256 | 384 | 512) {
  let bytesVar = Provable.witness(StaticBytes, () => staticBytes);
  let hash = SHA2.hash(len, bytesVar);

  zip(hash.bytes, (await sha2(len, longString())).bytes).forEach(
    ([a, b], i) => {
      a.assertEquals(b, `hash[${i}]`);
    }
  );
}

await test('sha256 inside circuit', async () => {
  await Provable.runAndCheck(() => circuit(256));
  await Provable.runAndCheck(() => circuitStatic(256));
});

await test('sha384 inside circuit', async () => {
  await Provable.runAndCheck(() => circuit(384));
  await Provable.runAndCheck(() => circuitStatic(384));
});

await test('sha512 inside circuit', async () => {
  await Provable.runAndCheck(() => circuit(512));
  await Provable.runAndCheck(() => circuitStatic(512));
});

// constraints

async function checkConstraints(len: 256 | 384 | 512) {
  let constraints = await Provable.constraintSystem(() => circuit(len));
  console.log(`\nsha2 ${len} constraints`);
  console.log('dynamic', constraints.rows);

  let constraintStatic = await Provable.constraintSystem(() =>
    circuitStatic(len)
  );
  console.log('static', constraintStatic.rows);

  let staticPadding =
    len === 256 ? SHA2.padding256(staticBytes) : SHA2.padding512(staticBytes);
  let dynamicPadding =
    len === 256 ? DynamicSHA2.padding256(bytes) : DynamicSHA2.padding512(bytes);

  let ratio = constraints.rows / constraintStatic.rows;
  console.log(`static # of bytes: ${staticBytes.length}`);
  console.log(`max dynamic # of bytes: ${bytes.maxLength}`);
  console.log(`static # of blocks: ${staticPadding.length}`);
  console.log(`max dynamic # of blocks: ${dynamicPadding.maxLength}`);
  console.log(
    `constraint overhead for dynamic: ${((ratio - 1) * 100).toFixed(2)}%`
  );
}

await test('constraints dynamic vs static (256)', () => checkConstraints(256));
await test('constraints dynamic vs static (512)', () => checkConstraints(512));

// reference implementation using the Web Crypto API

async function sha2(len: 256 | 384 | 512, input: string) {
  let buffer = await crypto.subtle.digest(
    `SHA-${len}`,
    new TextEncoder().encode(input)
  );
  return Bytes(len / 8).from(new Uint8Array(buffer));
}

// helpers

function toHexBytes(uint32: bigint | UInt32) {
  return UInt32.from(uint32).toBigint().toString(16).padStart(8, '0');
}
function blockToHexBytes(block: (bigint | UInt32)[]) {
  return block.map(toHexBytes);
}

function toHexBytes64(uint32: bigint | UInt64) {
  return UInt64.from(uint32).toBigInt().toString(16).padStart(16, '0');
}
function blockToHexBytes64(block: (bigint | UInt64)[]) {
  return block.map(toHexBytes64);
}

// ~400 bytes, needs 7 blocks, also contains unicode
function longString(): string {
  return `SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions designed by the
United States National Security Agency (NSA) and first published in 2001.[3][4]
They are built using the Merkle–Damgård construction, from a one-way compression function itself
built using the Davies–Meyer structure from a specialized block cipher.

SHA-2 includes significant changes from its predecessor, SHA-1.`;
}
