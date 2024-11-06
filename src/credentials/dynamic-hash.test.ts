import { DynamicArray } from './dynamic-array.ts';
import { DynamicString } from './dynamic-string.ts';
import './dynamic-record.ts';
import { hashDynamic, hashString } from './dynamic-hash.ts';
import { test } from 'node:test';
import * as nodeAssert from 'node:assert';
import { Bytes, MerkleList, Poseidon, Provable, UInt8 } from 'o1js';

let shortString = 'hi';
let ShortString = DynamicString({ maxLength: 5 });
let shortHash = hashString(shortString);

let longString =
  'Poseidon (/pəˈsaɪdən, pɒ-, poʊ-/;[1] Greek: Ποσειδῶν) is one of the Twelve Olympians';

let LongString = DynamicString({ maxLength: 100 });
let longHash = hashString(longString);

async function main() {
  await test('hash strings', () => {
    Provable.witness(ShortString, () => shortString)
      .hash()
      .assertEquals(shortHash, 'hash mismatch (short)');

    LongString.from(longString)
      .hash()
      .assertEquals(longHash, 'hash mismatch (long)');

    // we can even convert the `ShortString` into a `LongString`
    Provable.witness(LongString, () => ShortString.from(shortString))
      .hash()
      .assertEquals(shortHash, 'hash mismatch (short -> long)');

    // (the other way round doesn't work because the string is too long)
    nodeAssert.throws(() => {
      ShortString.from(LongString.from(longString));
    }, /larger than target size/);
  });

  let shortArray = [shortString, shortString];
  let ShortArray = DynamicArray(ShortString, { maxLength: 5 });
  let longArray = Array(8).fill(longString);
  let LongArray = DynamicArray(LongString, { maxLength: 10 });

  let shortArrayHash = hashDynamic(shortArray);
  let longArrayHash = hashDynamic(longArray);

  await test('hash arrays of strings', () => {
    Provable.witness(ShortArray, () => [shortString, shortString])
      .hash()
      .assertEquals(shortArrayHash, 'hash mismatch (short array)');

    Provable.witness(LongArray, () => Array(8).fill(longString))
      .hash()
      .assertEquals(longArrayHash, 'hash mismatch (long array)');
  });
}

await test('outside circuit', () => main());
await test('inside circuit', () => Provable.runAndCheck(main));

// comparison of constraint efficiency of different approaches

let cs = await Provable.constraintSystem(() => {
  Provable.witness(LongString, () => longString).hash();
});
console.log('constraints: string hash (100)', cs.rows);

// merkle list of characters
// list is represented as a single hash, so the equivalent of hashing is unpacking the entire list
let CharList = MerkleList.create(UInt8, (hash, { value }) =>
  Poseidon.hash([hash, value])
);

let cs2 = await Provable.constraintSystem(() => {
  Provable.witness(CharList, () =>
    CharList.from(Bytes.fromString(longString).bytes)
  ).forEach(100, (_item, _isDummy) => {});
});
console.log('constraints: merkle list of chars (100)', cs2.rows);
