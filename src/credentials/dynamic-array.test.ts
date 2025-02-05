import { Field, Provable, UInt8 } from 'o1js';
import { DynamicArray, DynamicString, toDecimalString } from '../dynamic.ts';
import assert from 'assert';

// concatenation of two strings

let String1 = DynamicString({ maxLength: 100 });
let String2 = DynamicString({ maxLength: 100 });

let StringLike1 = DynamicArray(UInt8, { maxLength: String1.maxLength });
let StringLike2 = DynamicArray(UInt8, { maxLength: String2.maxLength });
let String12 = DynamicString({
  maxLength: String1.maxLength + String2.maxLength,
});
let string1 = 'blub';
let string2 = 'blob';
let string12 = String12.from('blubblob');

console.log(
  'baseline',
  await runAndConstraints(() => {
    let s1 = Provable.witness(String1, () => string1);
    let s2 = Provable.witness(String2, () => string2);
  })
);

console.log(
  'baseline + chunk',
  await runAndConstraints(() => {
    let s1 = Provable.witness(String1, () => string1);
    let s2 = Provable.witness(String2, () => string2);
    s1.chunk(8);
  })
);

console.log(
  'concat naive',
  await runAndConstraints(() => {
    let s1 = Provable.witness(StringLike1, () => String1.from(string1));
    let s2 = Provable.witness(StringLike2, () => String2.from(string2));
    let s12 = s1.concat(s2);
    s12.assertEquals(string12);
  })
);

console.log(
  'concat transposed',
  await runAndConstraints(() => {
    let s1 = Provable.witness(String1, () => string1);
    let s2 = Provable.witness(String2, () => string2);

    let s12 = s1.concatTransposed(s2);
    new String12(s12.array, s12.length).assertEquals(string12);
  })
);

console.log(
  'concat with hashing',
  await runAndConstraints(() => {
    let s1 = Provable.witness(String1, () => string1);
    let s2 = Provable.witness(String2, () => string2);

    let s12 = s1.concatByHashing(s2);
    new String12(s12.array, s12.length).assertEquals(string12);
  })
);

console.log(
  'concat string',
  await runAndConstraints(() => {
    let s1 = Provable.witness(String1, () => string1);
    let s2 = Provable.witness(String2, () => string2);

    let s12 = s1.concat(s2);
    s12.assertEquals(string12);
  })
);

// substring check

{
  const String = DynamicString({ maxLength: 100 });
  const SmallString = DynamicString({ maxLength: 10 });

  function main() {
    let string = Provable.witness(String, () => 'hello world');
    let contained = Provable.witness(SmallString, () => 'lo wo');

    let i = string.assertContains(contained);
    i.assertEquals(3);

    if (Provable.inProver()) {
      let notContained = Provable.witness(SmallString, () => 'worldo');
      assert.throws(() => string.assertContains(notContained));
    }
  }
  function mainStatic() {
    let string = Provable.witness(String, () => 'hello world');
    let i = string.assertContains('lo wo');
    i.assertEquals(3);
  }

  // can run normally
  main();
  mainStatic();

  // can run while checking constraints
  console.log(
    `substring check (${SmallString.maxLength} in ${String.maxLength})`,
    await runAndConstraints(main)
  );
  console.log(
    `substring check static (5 in ${String.maxLength})`,
    await runAndConstraints(mainStatic)
  );
}

// test for DynamicArray.splitAt

{
  const String = DynamicString({ maxLength: 20 });

  function main() {
    let string = Provable.witness(String, () => 'hello world!');

    let [first, second] = string.splitAt(5);
    first.assertEquals('hello');
    second.assertEquals(' world!');

    let [all, empty] = string.splitAt(19);
    all.assertEquals(string);
    empty.assertEquals('');
    empty.length.assertEquals(0);
    assert(empty.maxLength === 1);
  }

  // can run normally
  main();

  // can run while checking constraints
  console.log(`splitAt`, await runAndConstraints(main));
}

// test for `toDecimalString()`

{
  function main() {
    let value = Provable.witness(Field, () => 1234);

    // note: 10 digits are just enough to represent any uint32
    let digits = toDecimalString(value, 10);
    digits.assertEquals('1234');
  }

  // can run normally
  main();

  // can run while checking constraints
  console.log(`toDecimalString`, await runAndConstraints(main));
}

// helper

async function runAndConstraints(fn: () => Promise<void> | void) {
  await Provable.runAndCheck(fn);
  return (await Provable.constraintSystem(fn)).rows;
}
