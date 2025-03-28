import {
  Bool,
  Field,
  type InferProvable,
  Option,
  Provable,
  UInt32,
  type InferValue,
  Gadgets,
  type ProvableHashable,
  type From,
  type ProvablePure,
  type IsPure,
  Poseidon,
  MerkleList,
} from 'o1js';
import { assert, assertHasProperty, chunk, fill, pad, zip } from '../util.ts';
import {
  type ProvableHashablePure,
  type ProvableHashableType,
  type ProvableHashableWide,
  ProvableType,
} from '../o1js-missing.ts';
import {
  assertInRange16,
  assertLessThan16,
  lessThan16,
  pack,
} from './gadgets.ts';
import { ProvableFactory } from '../provable-factory.ts';
import {
  deserializeProvable,
  deserializeProvableType,
  serializeProvable,
  serializeProvableType,
} from '../serialize-provable.ts';
import { TypeBuilder, TypeBuilderPure } from '../provable-type-builder.ts';
import { StaticArray } from './static-array.ts';
import { bitSize, packToField } from './dynamic-hash.ts';
import { BaseType } from './dynamic-base-types.ts';
import { type NestedProvableFor, NestedProvable } from '../nested.ts';
import { z } from 'zod';
import { SerializedTypeSchema, SerializedValueSchema } from '../validation.ts';

export { DynamicArray };

export {
  DynamicArrayBase,
  provable as provableDynamicArray,
  type DynamicArrayClass,
};

type DynamicArray<T = any, V = any> = DynamicArrayBase<T, V>;

type DynamicArrayClass<T, V> = typeof DynamicArrayBase<T, V> & {
  provable: ProvableHashableWide<DynamicArrayBase<T, V>, V[], (T | V)[]>;

  /**
   * Create a new DynamicArray from an array of values.
   *
   * Note: Both the actual length and the values beyond the original ones will be constant.
   */
  from(v: (T | V)[] | DynamicArrayBase<T, V>): DynamicArrayBase<T, V>;
};

type DynamicArrayClassPure<T, V> = typeof DynamicArrayBase<T, V> &
  Omit<DynamicArrayClass<T, V>, 'provable'> & {
    provable: ProvableHashableWide<DynamicArrayBase<T, V>, V[], (T | V)[]> &
      Omit<ProvablePure<DynamicArrayBase<T, V>, V[]>, 'fromValue'>;
  };

/**
 * Dynamic-length array type that has a
 * - constant max length, but
 * - dynamic actual length
 *
 * ```ts
 * const Bytes = DynamicArray(UInt8, { maxLength: 32 });
 * ```
 *
 * `maxLength` can be any number from 0 to 2^16-1.
 *
 * **Details**: Internally, this is represented as a static-sized array, plus a Field element
 * that represents the length.
 * The _only_ requirement on these is that the length is less or equal maxLength.
 * In particular, there are no provable guarantees maintained on the content of the static-sized array beyond the actual length.
 * Instead, our methods ensure integrity of array operations _within_ the actual length.
 */
function DynamicArray<
  A extends ProvableHashableType,
  T extends InferProvable<A> = InferProvable<A>,
  V extends InferValue<A> = InferValue<A>
>(
  type: A,
  options: { maxLength: number }
): IsPure<A, Field> extends true
  ? DynamicArrayClassPure<T, V>
  : DynamicArrayClass<T, V>;

function DynamicArray<
  A extends ProvableHashableType,
  T extends InferProvable<A> = InferProvable<A>,
  V extends InferValue<A> = InferValue<A>
>(
  type: A,
  {
    maxLength,
  }: {
    maxLength: number;
  }
): DynamicArrayClass<T, V> {
  // assert maxLength bounds
  assert(maxLength >= 0, 'maxLength must be >= 0');
  assert(maxLength < 2 ** 16, 'maxLength must be < 2^16');

  class DynamicArray_ extends DynamicArrayBase<T, V> {
    get innerType() {
      return type;
    }
    static get maxLength() {
      return maxLength;
    }
    static get provable() {
      return provableArray;
    }

    static from(input: (T | V)[] | DynamicArrayBase<T, V>) {
      return provableArray.fromValue(input);
    }
  }
  const provableArray = provable<T, V, typeof DynamicArrayBase<T, V>>(
    ProvableType.get(type),
    DynamicArray_
  ).build();

  return DynamicArray_;
}
BaseType.DynamicArray = DynamicArray;

class DynamicArrayBase<T = any, V = any> {
  /**
   * The internal array, which includes the actual values, padded up to `maxLength` with unconstrained values.
   */
  array: T[];

  /**
   * Length of the array. Guaranteed to be in [0, maxLength].
   */
  length: Field;

  // props to override
  get innerType(): ProvableHashableType<T, V> {
    throw Error('Inner type must be defined in a subclass.');
  }
  static get maxLength(): number {
    throw Error('Max length must be defined in a subclass.');
  }

  // derived prop
  get maxLength(): number {
    return (this.constructor as typeof DynamicArrayBase).maxLength;
  }

  constructor(array: T[], length: Field) {
    let maxLength = this.maxLength;
    assert(array.length === maxLength, 'input has to match maxLength');
    this.array = array;
    this.length = length;
  }

  /**
   * Asserts that 0 <= i < this.length, using a cached check that's not duplicated when doing it on the same variable multiple times.
   *
   * Cost: 1.5
   */
  assertIndexInRange(i: UInt32) {
    if (!this._indicesInRange.has(i.value)) {
      assertLessThan16(i, this.length);
      this._indicesInRange.add(i.value);
    }
  }

  /**
   * Gets value at index i, and proves that the index is in the array.
   *
   * Cost: TN + 1.5
   */
  get(i: UInt32): T {
    this.assertIndexInRange(i);
    return this.getOrUnconstrained(i.value);
  }

  /**
   * Gets a value at index i, as an option that is None if the index is not in the array.
   *
   * Note: The correct type for `i` is actually UInt16 which doesn't exist. The method is not complete (but sound) for i >= 2^16.
   *
   * Cost: TN + 2.5
   */
  getOption(i: UInt32): Option<T> {
    let type = this.innerType;
    let isContained = lessThan16(i.value, this.length);
    let value = this.getOrUnconstrained(i.value);
    const OptionT = Option(type);
    return OptionT.fromValue({ isSome: isContained, value });
  }

  /**
   * Gets a value at index i, ASSUMING that the index is in the array.
   *
   * If the index is in fact not in the array, the return value is completely unconstrained.
   *
   * **Warning**: Only use this if you already know/proved by other means that the index is within bounds.
   *
   * Cost: T*N where T = size of the type
   */
  getOrUnconstrained(i: Field): T {
    let type = ProvableType.get(this.innerType);
    let NULL = ProvableType.synthesize(type);
    let ai = Provable.witness(type, () => this.array[Number(i)] ?? NULL);
    let aiFields = type.toFields(ai);

    // assert a is correct on every field column with arrayGet()
    let fields = this.array.map((t) => type.toFields(t));

    for (let j = 0; j < type.sizeInFields(); j++) {
      let column = fields.map((x) => x[j]!);
      Gadgets.arrayGet(column, i).assertEquals(aiFields[j]!);
    }
    return ai;
  }

  /**
   * Sets a value at index i and proves that the index is in the array.
   *
   * Cost: 1.5(T + 1)N + 1.5
   */
  set(i: UInt32, value: T): void {
    this.assertIndexInRange(i);
    this.setOrDoNothing(i.value, value);
  }

  /**
   * Sets a value at index i, or does nothing if the index is not in the array
   *
   * Cost: 1.5(T + 1)N
   */
  setOrDoNothing(i: Field, value: T): void {
    zip(this.array, this._indexMask(i)).forEach(([t, equalsIJ], j) => {
      this.array[j] = Provable.if(equalsIJ, this.innerType, value, t);
    });
  }

  /**
   * Map every element of the array to a new value.
   *
   * **Warning**: The callback will be passed unconstrained dummy values.
   */
  map<S extends ProvableHashableType>(
    type: S,
    f: (t: T, i: number) => From<S>
  ): DynamicArray<InferProvable<S>, InferValue<S>> {
    let Array = DynamicArray(type, { maxLength: this.maxLength });
    let provable = ProvableType.get(type);
    let array = this.array.map((x, i) => provable.fromValue(f(x, i)));
    let newArray = new Array(array, this.length);

    // new array has same length/maxLength, so it can use the same cached masks
    newArray._indexMasks = this._indexMasks;
    newArray._indicesInRange = this._indicesInRange;
    newArray.__dummyMask = this.__dummyMask;
    return newArray;
  }

  /**
   * Iterate over all elements of the array.
   *
   * The callback will be passed an element and a boolean `isDummy` indicating whether the value is part of the actual array.
   */
  forEach(f: (t: T, isDummy: Bool, i: number) => void) {
    zip(this.array, this._dummyMask()).forEach(([t, isDummy], i) => {
      f(t, isDummy, i);
    });
  }

  /**
   * Iterate over all elements of the array, in reverse order.
   *
   * The callback will be passed an element and a boolean `isDummy` indicating whether the value is part of the actual array.
   *
   * Note: the indices are also passed in reverse order, i.e. we always have `t = this.array[i]`.
   */
  forEachReverse(f: (t: T, isDummy: Bool, i: number) => void) {
    zip(this.array, this._dummyMask())
      .toReversed()
      .forEach(([t, isDummy], i) => {
        f(t, isDummy, this.maxLength - 1 - i);
      });
  }

  /**
   * Reduce the array to a single value.
   *
   * The callback will be passed the current state, an element, and a boolean `isDummy` indicating whether the value is part of the actual array.
   */
  reduce<S>(
    stateType: NestedProvableFor<S>,
    state: S,
    f: (state: S, t: T, isDummy: Bool) => S
  ): S {
    let type = NestedProvable.get(stateType);
    this.forEach((t, isDummy) => {
      let newState = f(state, t, isDummy);
      state = Provable.if(isDummy, type, state, newState);
    });
    return state;
  }

  /**
   * Split the array at index i, i.e. returns `[slice(0, i), slice(i)]`.
   *
   * If i is 0, the first array will be empty.
   * If i it >= the length, the second array will be empty.
   *
   * Note: this method uses very few constraints, it's only rearranging the array contents
   * and recomputing the two lengths.
   */
  splitAt(i: number): [DynamicArray<T, V>, DynamicArray<T, V>] {
    assert(i >= 0 && i < 1 << 16, 'index must be in [0, 2^16)');
    let maxLength1 = Math.min(i, this.maxLength);
    let maxLength2 = Math.max(this.maxLength - i, 0);

    let Array1 = DynamicArray(this.innerType, { maxLength: maxLength1 });
    let Array2 = DynamicArray(this.innerType, { maxLength: maxLength2 });
    let array1 = this.array.slice(0, maxLength1);
    let array2 = this.array.slice(maxLength1);

    let ltLength = lessThan16(Field(i), this.length);
    let length1 = Provable.if(ltLength, Field(i), this.length);
    let length2 = Provable.if(ltLength, this.length.sub(Field(i)), Field(0));

    return [new Array1(array1, length1), new Array2(array2, length2)];
  }

  /**
   * Equivalent to `Array.slice(start)`. Supports variable start index.
   */
  slice(start: number | UInt32): DynamicArray<T, V> {
    if (typeof start === 'number') return this.splitAt(start)[1];

    let Array = DynamicArray(this.innerType, { maxLength: this.maxLength });
    let length = this.length.sub(start.value).seal();
    Gadgets.rangeCheck16(length);
    // note: these values are constrained if the index is in the new range
    // i < length - start => start + i < length
    let array = this.array.map((_, i) =>
      this.getOrUnconstrained(start.value.add(i))
    );
    return new Array(array, length);
  }

  /**
   * Returns a new array with the elements reversed.
   */
  reverse(): DynamicArray<T, V> {
    let Array = DynamicArray(this.innerType, { maxLength: this.maxLength });
    // first, reverse the full array
    let array = this.array.toReversed();

    // `array` is not yet what we need, since it has all the padding at the beginning
    // so, slice off the padding
    let maxLength = Field(this.maxLength);
    return new Array(array, maxLength).slice(
      UInt32.Unsafe.fromField(maxLength.sub(this.length).seal())
    );
  }

  /**
   * Dynamic array hash that only depends on the actual values (not the padding).
   *
   * Avoids hash collisions by encoding the number of actual elements at the beginning of the hash input.
   */
  hash() {
    let type = ProvableType.get(this.innerType);

    // pack all elements into a single field element
    let fields = this.array.map((x) => packToField(x, type));
    let NULL = packToField(ProvableType.synthesize(type), type);

    // assert that all padding elements are 0. this allows us to pack values into blocks
    zip(fields, this._dummyMask()).forEach(([x, isPadding]) => {
      Provable.assertEqualIf(isPadding, Field, x, NULL);
    });

    // create blocks of 2 field elements each
    // TODO abstract this into a `chunk()` method that returns a DynamicArray<StaticArray<T>>
    let elementSize = bitSize(type);
    if (elementSize === 0) elementSize = 1; // edge case for empty types like `Undefined`
    let elementsPerHalfBlock = Math.floor(254 / elementSize);
    if (elementsPerHalfBlock === 0) elementsPerHalfBlock = 1; // larger types are compressed

    let elementsPerBlock = 2 * elementsPerHalfBlock;

    // we pack the length at the beginning of the first block
    // for efficiency (to avoid unpacking the length), we first put zeros at the beginning
    // and later just add the length to the first block
    let elementsPerUint32 = Math.max(Math.floor(32 / elementSize), 1);
    let array = fill(elementsPerUint32, Field(0)).concat(fields);

    let maxBlocks = Math.ceil(
      (elementsPerUint32 + this.maxLength) / elementsPerBlock
    );
    let padded = pad(array, maxBlocks * elementsPerBlock, NULL);
    let chunked = chunk(padded, elementsPerBlock);
    let blocks = chunked.map((block): [Field, Field] => {
      let firstHalf = block.slice(0, elementsPerHalfBlock);
      let secondHalf = block.slice(elementsPerHalfBlock);
      return [pack(firstHalf, elementSize), pack(secondHalf, elementSize)];
    });

    // add length to the first block
    let firstBlock = blocks[0]!;
    firstBlock[0] = firstBlock[0].add(this.length).seal();

    let Fieldx2 = StaticArray(Field, 2);
    let Blocks = DynamicArray(Fieldx2, { maxLength: maxBlocks });

    // nBlocks = ceil(length / elementsPerBlock) = floor((length + elementsPerBlock - 1) / elementsPerBlock)
    let nBlocks = UInt32.Unsafe.fromField(
      this.length.add(elementsPerUint32 + elementsPerBlock - 1)
    ).div(elementsPerBlock).value;
    let dynBlocks = new Blocks(blocks.map(Fieldx2.from), nBlocks);

    // now hash the 2-field elements blocks, one permutation at a time
    // note: there's a padding element included at the end in the case of uneven number of blocks
    // however, this doesn't cause hash collisions because we encoded the length at the beginning
    let state = Poseidon.initialState();
    dynBlocks.forEach((block, isPadding) => {
      let newState = Poseidon.update(state, block.array);
      state[0] = Provable.if(isPadding, state[0], newState[0]);
      state[1] = Provable.if(isPadding, state[1], newState[1]);
      state[2] = Provable.if(isPadding, state[2], newState[2]);
    });
    return state[0];
  }

  /**
   * Convert the array to a MerkleList.
   */
  merkelize(listHash?: (hash: Field, t: T) => Field): MerkleList<T> {
    let type = this.innerType;
    listHash ??= (h, t) => Poseidon.hash([h, packToField(t, type)]);
    const List = MerkleList.create(type, listHash);
    let list = List.empty();
    this.forEach((t, isDummy) => {
      list.pushIf(isDummy.not(), t);
    });
    return list;
  }

  /**
   * Returns a dynamic number of full chunks and a final, smaller chunk.
   *
   * If the array is evenly divided into chunks, the final chunk has length 0.
   *
   * Note: This method uses very few constraints, it's mostly rearranging the array contents
   * doing a small amount of math on the lengths, and a single `get()` operation on the chunked array.
   */
  chunk(
    chunkSize: number
  ): [DynamicArray<StaticArray<T, V>, V[]>, DynamicArray<T, V>] {
    let type = ProvableType.get(this.innerType);

    let maxChunks = Math.floor(this.maxLength / chunkSize);
    let maxChunksCeil = Math.ceil(this.maxLength / chunkSize);
    let Chunk = StaticArray(type, chunkSize);
    let DynamicChunk = DynamicArray(type, { maxLength: chunkSize });
    let Chunks = DynamicArray(Chunk, { maxLength: maxChunks });

    let NULL = ProvableType.synthesize(type);
    let padded = pad(this.array, maxChunksCeil * chunkSize, NULL);
    let completeChunks = padded.slice(0, maxChunks * chunkSize);
    let chunked = chunk(completeChunks, chunkSize).map(Chunk.from);

    // nChunks = floor(length / chunkSize)
    let length = UInt32.Unsafe.fromField(this.length);
    let { quotient: nChunks, rest: lastChunkLength } = length.divMod(chunkSize);
    let chunks = new Chunks(chunked, nChunks.value);

    // last chunk is the chunk at `nChunks`, of the fully padded array
    let lastChunkPadded = StaticArray(Chunk, maxChunksCeil)
      .from(chunk(padded, chunkSize))
      // this `get()` can only be out of bounds if maxChunksCeil = ceil(maxLength / chunkSize) <= nChunks = floor(length / chunkSize)
      // which implies length == maxLength == maxChunksCeil * chunkSize
      // which implies lastChunkLength == 0; in which case we don't care about the actual values in this chunk
      .getOrUnconstrained(nChunks.value);

    let lastChunk = new DynamicChunk(
      lastChunkPadded.array,
      lastChunkLength.value
    );
    return [chunks, lastChunk];
  }

  /**
   * Assert that the array is exactly equal, in its representation in field elements, to another array.
   *
   * Warning: Also checks equality of the padding and maxLength, which don't contribute to the "meaningful" part of the array.
   * Therefore, this method is mainly intended for testing.
   */
  assertEqualsStrict(other: DynamicArray<T, V>) {
    assert(this.maxLength === other.maxLength, 'max length mismatch');
    this.length.assertEquals(other.length, 'length mismatch');
    zip(this.array, other.array).forEach(([a, b]) => {
      Provable.assertEqual(this.innerType, a, b);
    });
  }

  /**
   * Assert that this array is equal to another.
   *
   * Note: This only requires the length and the actual elements to be equal, not the padding or the maxLength.
   * To check for exact equality, use `assertEqualsStrict()`.
   */
  assertEquals(other: DynamicArray<T, V> | StaticArray<T, V> | (T | V)[]) {
    this.length.assertEquals(other.length, 'length mismatch');
    let otherArray = Array.isArray(other) ? other : other.array;
    let type = ProvableType.get(this.innerType);
    let NULL = ProvableType.synthesize(type);
    this.forEach((t, isDummy, i) => {
      let s = type.fromValue(otherArray[i] ?? NULL);
      Provable.assertEqualIf(isDummy.not(), type, t, s);
    });
  }

  /**
   * Concatenate two arrays.
   *
   * The resulting (max)length is the sum of the two individual (max)lengths.
   *
   * **Warning**: This method takes effort proportional to (M + N)*N where M, N are the two maxlengths.
   * It's only recommended to use if at least one of the arrays is small.
   */
  concat(other: DynamicArray<T, V>): DynamicArray<T, V> {
    // witness combined array
    let CombinedArray = DynamicArray(this.innerType, {
      maxLength: this.maxLength + other.maxLength,
    });
    let combinedArray = Provable.witness(CombinedArray, () =>
      this.array
        .slice(0, Number(this.length))
        .concat(other.array.slice(0, Number(other.length)))
    );

    // length has to be the sum of the lengths
    this.length.add(other.length).assertEquals(combinedArray.length);

    // combined array has to contain the first array, starting from the beginning
    this.forEach((t, isDummy, i) => {
      let s = combinedArray.array[i]!;
      Provable.assertEqualIf(isDummy.not(), this.innerType, t, s);
    });

    // combined array has to contain the second array, starting from the end of the first array
    other.forEach((t, isDummy, i) => {
      let j = this.length.add(i); // this is guaranteed to be within bounds, if isDummy is false
      let s = combinedArray.getOrUnconstrained(j);
      Provable.assertEqualIf(isDummy.not(), other.innerType, t, s);
    });

    // we don't care what else is in the combined array!
    return combinedArray;
  }

  /**
   * Concatenate two arrays.
   *
   * Alternative to `concat()` that takes effort proportional to (M + N)*M where M, N are the two maxlengths,
   * and also has a better constant.
   *
   * Note: This is better than `concat()` if the arrays are about equal or the first array is smaller.
   * It's worse is the first array is much larger than the second.
   */
  concatTransposed(
    other: DynamicArray<T, V> | StaticArray<T, V>
  ): DynamicArray<T, V> {
    // construct 2D array of all possible combinations depending on a's length
    // [b0, b1, b2, ... ],
    // [a0, b0, b1, ... ],
    // [a0, a1, b0, ... ], etc
    let a = this.array;
    let b = other.array;
    let NULL = ProvableType.synthesize(this.innerType);
    let Column = StaticArray(this.innerType, this.maxLength + 1);

    let maxLength = this.maxLength + other.maxLength;
    let array2D = Array.from({ length: this.maxLength + 1 }, (_, i) =>
      pad(a.slice(0, i).concat(b), maxLength, NULL)
    );
    let arrayTransposed = Array.from({ length: maxLength }, (_, j) =>
      Column.from(array2D.map((row) => row[j]!))
    );
    let array = arrayTransposed.map((a) => a.getOrUnconstrained(this.length));
    let length = this.length.add(other.length).seal();

    let CombinedArray = DynamicArray(this.innerType, { maxLength });
    return new CombinedArray(array, length);
  }

  /**
   * Concatenate two arrays.
   *
   * Alternative to `concat()` that proves correctness of the concatenated array
   * by Poseidon-hashing it element by element. In contrast to `concat()`, the effort is linear in N + M,
   * but with a larger constant.
   *
   * The resulting (max)length is the sum of the two individual (max)lengths.
   */
  concatByHashing(other: DynamicArray<T, V>): DynamicArray<T, V> {
    // witness combined array
    let type = ProvableType.get(this.innerType);
    let CombinedArray = DynamicArray(type, {
      maxLength: this.maxLength + other.maxLength,
    });
    let combinedArray = Provable.witness(CombinedArray, () =>
      this.array
        .slice(0, Number(this.length))
        .concat(other.array.slice(0, Number(other.length)))
    );

    // hash the combined array, element by element
    let hash = Field(0);
    combinedArray.forEach((t, isDummy) => {
      let newHash = Poseidon.hash([hash, packToField(t, type)]);
      hash = Provable.if(isDummy, hash, newHash);
    });

    // hash the first array and then the second array, element by element
    let hash1 = Field(0);
    this.forEach((t, isDummy) => {
      let newHash = Poseidon.hash([hash1, packToField(t, type)]);
      hash1 = Provable.if(isDummy, hash1, newHash);
    });
    other.forEach((t, isDummy) => {
      let newHash = Poseidon.hash([hash1, packToField(t, type)]);
      hash1 = Provable.if(isDummy, hash1, newHash);
    });

    // the two hashes must be equal
    hash.assertEquals(hash1);
    // lengths must be equal as well (this was implicitly proved by the hash as well)
    combinedArray.length.assertEquals(this.length.add(other.length));

    return combinedArray;
  }

  /**
   * Push a value, without changing the maxLength.
   *
   * Proves that the new length is still within the maxLength, fails otherwise.
   *
   * To grow the maxLength along with the actual length, you can use:
   *
   * ```ts
   * array = array.growMaxLengthBy(1);
   * array.push(value);
   * ```
   *
   * Cost: 1.5(T + 1)N + 2
   */
  push(value: T): void {
    let oldLength = this.length;
    this.length = oldLength.add(1).seal();
    assertInRange16(this.length, this.maxLength);
    this.setOrDoNothing(oldLength, value);
  }

  /**
   * Return a version of the same array with a larger maxLength.
   *
   * **Warning**: Does not modify the array, but returns a new one.
   *
   * **Note**: this doesn't cost constraints, but currently doesn't preserve any cached constraints.
   */
  growMaxLengthTo(maxLength: number): DynamicArray<T, V> {
    assert(
      maxLength >= this.maxLength,
      'new maxLength must be greater or equal'
    );
    let NewArray = DynamicArray(this.innerType, { maxLength });
    let NULL = ProvableType.synthesize(this.innerType);
    let array = pad(this.array, maxLength, NULL);
    let length = this.length;
    return new NewArray(array, length);
  }

  /**
   * Return a version of the same array with a larger maxLength.
   *
   * **Warning**: Does not modify the array, but returns a new one.
   *
   * **Note**: this doesn't cost constraints, but currently doesn't preserve any cached constraints.
   */
  growMaxLengthBy(maxLength: number): DynamicArray<T, V> {
    return this.growMaxLengthTo(this.maxLength + maxLength);
  }

  /**
   * Mutate this array such that all elements beyond the actual length are set to an empty value.
   */
  normalize() {
    let NULL = ProvableType.synthesize(this.innerType);
    this.forEach((t, isPadding, i) => {
      this.array[i] = Provable.if(isPadding, this.innerType, NULL, t);
    });
  }

  /**
   * Assert that the array is normalized, i.e. all padding elements are empty.
   *
   * Note: For completeness, it is probably better to use `normalize()` which uses the same amount
   * of constraints and comes with the same guarantee.
   */
  assertNormalized() {
    let NULL = ProvableType.synthesize(this.innerType);
    this.forEach((t, isPadding) => {
      // TODO this needs a message argument!
      Provable.assertEqualIf(isPadding, this.innerType, t, NULL);
    });
  }

  // cached variables to not duplicate constraints if we do something like array.get(i), array.set(i, ..) on the same index
  _indexMasks: Map<Field, Bool[]> = new Map();
  _indicesInRange: Set<Field> = new Set();
  __dummyMask?: Bool[];

  /**
   * Compute i.equals(j) for all indices j in the static-size array.
   *
   * Costs: 1.5N
   *
   * TODO: equals() could be optimized to just 1 double generic because j is constant, o1js doesn't do that
   */
  _indexMask(i: Field) {
    let mask = this._indexMasks.get(i);
    mask ??= this.array.map((_, j) => i.equals(j));
    this._indexMasks.set(i, mask);
    return mask;
  }

  /**
   * Tells us which elements are dummies = not actually in the array.
   *
   * 0 0 0 1 1 1 1
   *       ^
   *       length
   */
  _dummyMask() {
    if (this.__dummyMask !== undefined) return this.__dummyMask;
    let isLength = this._indexMask(this.length);
    let wasLength = Bool(false);

    let mask = isLength.map((isLength) => {
      wasLength = wasLength.or(isLength);
      return wasLength;
    });
    this.__dummyMask = mask;
    return mask;
  }

  /**
   * Returns true if the index is a dummy index,
   * i.e. not actually in the array.
   */
  isDummyIndex(i: number) {
    return this._dummyMask()[i];
  }

  toValue() {
    assertHasProperty(this.constructor, 'provable', 'Need subclass');
    return (this.constructor.provable as Provable<this, V[]>).toValue(this);
  }

  /**
   * Assert that this array contains the given subarray, and returns the index where it starts.
   */
  assertContains(
    subarray: DynamicArray<T, V> | StaticArray<T, V>,
    message?: string
  ) {
    let type = this.innerType;
    assert(subarray.maxLength <= this.maxLength, 'subarray must be smaller');

    // idea: witness an index i and show that the subarray is contained at i
    let i = Provable.witness(Field, () => {
      let length = Number(this.length);
      let sublength = Number(subarray.length);
      if (sublength === 0) return 0n;
      for (let i = 0; i < length; i++) {
        // check if subarray is contained at i
        let isContained = true;
        for (let j = 0; j < sublength; j++) {
          if (i + j >= length) return -1n;
          isContained &&= Provable.equal(
            type,
            this.array[i + j]!,
            subarray.array[j]!
          ).toBoolean();
        }
        if (isContained) return BigInt(i);
      }
      return -1n;
    });
    // explicit constraint for !== -1, just to get a nice error message
    // TODO: would be better to have error message in `Gadgets.rangeCheck16()`
    i.assertNotEquals(-1, message ?? 'Array does not contain subarray');

    // i + subarray.length - 1 < this.length
    Gadgets.rangeCheck16(i);
    this.assertIndexInRange(
      UInt32.Unsafe.fromField(i.add(subarray.length).sub(1))
    );

    // assert that subarray is contained at i
    // cost: M*(N*T + O(1))
    let j = 0;
    if (subarray instanceof DynamicArrayBase) {
      subarray.forEach((si, isDummy) => {
        let ai = this.getOrUnconstrained(i.add(j));
        Provable.assertEqualIf(isDummy.not(), type, si, ai);
        j++;
      });
    } else {
      subarray.forEach((si) => {
        let ai = this.getOrUnconstrained(i.add(j));
        Provable.assertEqual(type, si, ai);
        j++;
      });
    }

    return i;
  }
}

/**
 * Base class of all DynamicArray subclasses
 */
DynamicArray.Base = DynamicArrayBase;

function provable<T, V, Class extends typeof DynamicArrayBase<T, V>>(
  type: ProvableHashablePure<T, V>,
  Class: Class
): TypeBuilderPure<InstanceType<Class>, V[]>;

function provable<T, V, Class extends typeof DynamicArrayBase<T, V>>(
  type: ProvableHashable<T, V>,
  Class: Class
): TypeBuilder<InstanceType<Class>, V[]>;

function provable<T, V, Class extends typeof DynamicArrayBase<T, V>>(
  type: ProvableHashable<T, V>,
  Class: Class
) {
  let maxLength = Class.maxLength;
  let NULL = ProvableType.synthesize(type);

  return (
    TypeBuilder.shape({
      array: Provable.Array(type, maxLength),
      length: Field,
    })
      .forConstructor((t) => new Class(t.array, t.length))

      // check has to validate length in addition to the other checks
      .withAdditionalCheck(({ length }) => {
        assertInRange16(length, maxLength);
      })

      // convert to/from plain array that has the _actual_ length
      .mapValue<V[]>({
        there({ array, length }) {
          return array.slice(0, Number(length));
        },
        backAndDistinguish(array) {
          // gracefully handle different maxLength
          if (array instanceof DynamicArrayBase) {
            if (array.maxLength === maxLength) return array;
            array = array.toValue();
          }
          // fully convert back so that we can pad with NULL
          let converted = array.map((x) => type.fromValue(x));
          let padded = pad(converted, maxLength, NULL);
          return new Class(padded, Field(array.length));
        },
      })

      // custom hash input
      .hashInput((array) => {
        return { fields: [array.hash()] };
      })
  );
}

// serialize/deserialize

ProvableFactory.register('DynamicArray', DynamicArray, {
  typeSchema: z.object({
    maxLength: z.number(),
    innerType: SerializedTypeSchema,
  }),
  valueSchema: z.array(SerializedValueSchema),

  typeToJSON(constructor) {
    return {
      maxLength: constructor.maxLength,
      innerType: serializeProvableType(constructor.prototype.innerType),
    };
  },

  typeFromJSON(json) {
    let innerType = deserializeProvableType(json.innerType);
    return DynamicArray(innerType as ProvableHashableType, {
      maxLength: json.maxLength,
    });
  },

  valueToJSON(_, { array, length }) {
    return array.slice(0, Number(length)).map((v) => serializeProvable(v));
  },

  valueFromJSON(type, value) {
    let array = value.map((v) => deserializeProvable(v));
    return type.from(array);
  },
});
