import { Bool, Field, Provable, Struct, UInt32, UInt64 } from 'o1js';
import { DynamicRecord } from './dynamic-record.ts';
import { DynamicString } from './dynamic-string.ts';
import { test } from 'node:test';
import assert from 'assert';
import { hashCredential } from '../credential.ts';
import { owner } from '../../tests/test-utils.ts';
import { hashDynamic, hashRecord } from './dynamic-hash.ts';
import { DynamicArray } from './dynamic-array.ts';
import { Schema } from './schema.ts';

const String5 = DynamicString({ maxLength: 5 });
const String20 = DynamicString({ maxLength: 20 });

// original schema, data and hash from known layout

const OriginalSchema = Schema({
  first: Field,
  second: Schema.Boolean,
  third: Schema.String,
  fourth: UInt32,
  fifth: {
    field: Schema.Number,
    string: Schema.String,
  },
  sixth: Schema.Array(Schema.Number),
});

let original = OriginalSchema.from({
  first: 1,
  second: true,
  third: 'something',
  fourth: 123n,
  fifth: { field: 2, string: '...' },
  sixth: [1, 2, 3],
});
const expectedHash = hashRecord(original);

const OriginalWrappedInStruct = Struct(OriginalSchema.nestedType(original));
let originalStruct = OriginalWrappedInStruct.fromValue(original);

// subset schema and circuit that doesn't know the full original layout

const Subschema = DynamicRecord(
  {
    // different max length of string/array properties
    third: String20,
    // not necessarily in original order
    first: Field,
    // subset in nested schema
    fifth: DynamicRecord(
      {
        // different max length here as well
        string: String5,
      },
      { maxEntries: 5 }
    ),
  },
  { maxEntries: 10 }
);

// original schema is compatible
Subschema.from(original);
Subschema.from(originalStruct);

async function circuit() {
  let record = Provable.witness(Subschema, () => original);

  await test('DynamicRecord.get()', () => {
    // static field
    record.get('first').assertEquals(1, 'first');

    // dynamic string with different max length
    record.get('third').assertEqualsStrict(String20.from('something'));

    // nested subschema
    let fifthString = record.get('fifth').get('string');
    fifthString.assertEqualsStrict(String5.from('...'));
  });

  await test('DynamicRecord.getAny()', () => {
    // we can get the other fields as well, if we know their type
    record.getAny(Bool, 'second').assertEquals(true, 'second');
    record.getAny(UInt32, 'fourth').assertEquals(UInt32.from(123n));

    // `packToField()` collisions mean that we can also reinterpret fields into types with equivalent packing
    // (if the new type's `fromValue()` allows the original value)
    record.getAny(Bool, 'first').assertEquals(true, 'first');
    record.getAny(UInt64, 'first').assertEquals(UInt64.one);
    record.getAny(UInt64, 'fourth').assertEquals(UInt64.from(123n));

    // we can get a nested record as struct (and nested strings can have different length)
    // this works because structs are hashed in dynamic record style
    const FifthStruct = Struct({ field: UInt64, string: String20 });
    let fifth = record.getAny(FifthStruct, 'fifth');
    Provable.assertEqual(
      FifthStruct,
      fifth,
      FifthStruct.fromValue(original.fifth)
    );

    // can get an array as dynamic array, as long as the maxLength is >= the actual length
    const SixthDynamic = DynamicArray(UInt64, { maxLength: 7 });
    let sixth = record.getAny(SixthDynamic, 'sixth');
    sixth.assertEqualsStrict(SixthDynamic.from(original.sixth));

    const SixthDynamicShort = DynamicArray(Field, { maxLength: 2 });
    assert.throws(
      () => record.getAny(SixthDynamicShort, 'sixth'),
      /larger than target size/
    );

    // can't get a missing key
    assert.throws(() => record.getAny(Bool, 'missing'), /Key not found/);
  });

  await test('DynamicRecord.hash()', () =>
    record.hash().assertEquals(expectedHash, 'hash'));

  await test('hashDynamic()', () => {
    hashDynamic(original).assertEquals(expectedHash);
    hashDynamic(originalStruct).assertEquals(expectedHash);
    hashDynamic(record).assertEquals(expectedHash);
  });

  await test('hashCredential()', () => {
    let originalHash = hashCredential({ owner, data: original });
    let originalStructHash = hashCredential({ owner, data: originalStruct });

    originalStructHash.assertEquals(originalHash, 'hashCredential() (struct)');

    let subschemaHash = hashCredential({ owner, data: record });
    subschemaHash.assertEquals(
      originalHash,
      'hashCredential() (dynamic record)'
    );
  });
}

await test('outside circuit', () => circuit());
await test('inside circuit', () => Provable.runAndCheck(circuit));
