import { Bytes, Keccak, Provable } from 'o1js';
import { DynamicSHA3 } from './dynamic-sha3.ts';
import { stringLength } from '../util.ts';
import { DynamicString } from './dynamic-string.ts';
import test from 'node:test';

let longMessage =
  'SHA-3 (Secure Hash Algorithm 3) is the latest[4] member of the Secure Hash Algorithm family of standards, released by NIST on August 5, 2015.[5][6][7] Although part of the same series of standards, SHA-3 is internally different from the MD5-like structure of SHA-1 and SHA-2. ';

const String = DynamicString({ maxLength: 300 });
const StaticBytes = Bytes(stringLength(longMessage));
const Bytes32 = Bytes(32);

// test against reference implementation from o1js

const string = String.from(longMessage);
const staticBytes = StaticBytes.fromString(longMessage);
const expectedHash = Keccak.ethereum(staticBytes);

await test('keccak256 outside circuit', async () => {
  await circuit();
  await circuitStatic();
});

await test('keccak256 in circuit', async () => {
  await Provable.runAndCheck(() => circuit());
  await Provable.runAndCheck(() => circuitStatic());
});

// constraints
let constraints = await Provable.constraintSystem(() => circuit());
let constraintStatic = await Provable.constraintSystem(() => circuitStatic());

console.log(`\nkeccak256 constraints`);
console.log('dynamic', constraints.rows);
console.log('static', constraintStatic.rows);

let ratio = constraints.rows / constraintStatic.rows;
console.log(`static # of bytes: ${staticBytes.length}`);
console.log(`max dynamic # of bytes: ${string.maxLength}`);
console.log(
  `constraint overhead for dynamic: ${((ratio - 1) * 100).toFixed(2)}%`
);

async function circuit() {
  let message = Provable.witness(String, () => longMessage);
  let hash = DynamicSHA3.keccak256(message);
  Provable.assertEqual(Bytes32, hash, expectedHash);
}

async function circuitStatic() {
  let message = Provable.witness(StaticBytes, () => staticBytes);
  let hash = Keccak.ethereum(message);
  Provable.assertEqual(Bytes32, hash, expectedHash);
}
