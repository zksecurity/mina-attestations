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
} from 'o1js';
import { assert, assertHasProperty, chunk, zip } from '../util.ts';
import { type ProvableHashableWide, ProvableType } from '../o1js-missing.ts';
import { assertLessThan16, lessThan16 } from './gadgets.ts';
import { TypeBuilder } from '../provable-type-builder.ts';

export { StaticArray };

type StaticArray<T = any, V = any> = StaticArrayBase<T, V>;

type StaticArrayClass<A, T, V> = typeof StaticArrayBase<T, V> & {
  provable: ProvableHashableWide<StaticArrayBase<T, V>, V[], (T | From<A>)[]>;

  /**
   * Create a new StaticArray from an array of values.
   */
  from(v: (T | From<A>)[] | StaticArrayBase<T, V>): StaticArrayBase<T, V>;
};

type StaticArrayClassPure<A, T, V> = typeof StaticArrayBase<T, V> &
  Omit<StaticArrayClass<A, T, V>, 'provable'> & {
    provable: ProvableHashableWide<
      StaticArrayBase<T, V>,
      V[],
      (T | From<A>)[]
    > &
      Omit<ProvablePure<StaticArrayBase<T, V>, V[]>, 'fromValue'>;
  };

/**
 * Array with a fixed number of elements and several helper methods.
 *
 * ```ts
 * const Bytes32 = StaticArray(UInt8, 32);
 * ```
 *
 * The second parameter is the `length`. It can be any number from 0 to 2^16-1.
 */
function StaticArray<
  A extends ProvableType,
  T extends InferProvable<A> = InferProvable<A>,
  V extends InferValue<A> = InferValue<A>
>(
  type: A,
  length: number
): IsPure<A, Field> extends true
  ? StaticArrayClassPure<A, T, V>
  : StaticArrayClass<A, T, V>;

function StaticArray<
  A extends ProvableType,
  T extends InferProvable<A> = InferProvable<A>,
  V extends InferValue<A> = InferValue<A>
>(type: A, length: number): StaticArrayClass<A, T, V> {
  let innerType: Provable<T, V> = ProvableType.get(type);

  // assert length bounds
  assert(length >= 0, 'length must be >= 0');
  assert(length < 2 ** 16, 'length must be < 2^16');

  const provableArray = TypeBuilder.shape({
    array: Provable.Array(innerType, length),
  })
    .forConstructor<StaticArrayBase<T, V>>(
      ({ array }) => new StaticArray_(array)
    )
    // convert to/from plain array
    .mapValue<V[]>({
      there: ({ array }) => array,
      back: (array) => ({ array }),
      distinguish: (s) => s instanceof StaticArrayBase,
    })
    .build();

  class StaticArray_ extends StaticArrayBase<T, V> {
    get innerType() {
      return innerType;
    }
    static get length() {
      return length;
    }

    static from(input: (T | V)[] | StaticArrayBase<T, V>) {
      return provableArray.fromValue(input);
    }

    static provable = provableArray;
  }
  return StaticArray_;
}

StaticArray.from = function <A extends ProvableType>(
  type: A,
  array: From<A>[]
) {
  return StaticArray(type, array.length).from(array);
};

class StaticArrayBase<T = any, V = any> {
  /**
   * The plain array
   */
  array: T[];

  // props to override
  get innerType(): Provable<T, V> {
    throw Error('Inner type must be defined in a subclass.');
  }
  static get length(): number {
    throw Error('Length must be defined in a subclass.');
  }

  // derived prop
  get length(): number {
    return (this.constructor as typeof StaticArrayBase).length;
  }
  /**
   * The `length` of the array. For compatibility with `DynamicArray`, we also provide is under `maxLength`.
   */
  get maxLength() {
    return this.length;
  }

  constructor(array: T[]) {
    assert(array.length === this.length, 'input has to match length');
    this.array = array;
  }

  *[Symbol.iterator]() {
    for (let a of this.array) yield a;
  }

  /**
   * Asserts that 0 <= i < this.length, using a cached check that's not duplicated when doing it on the same variable multiple times.
   *
   * Handles constants without creating constraints.
   *
   * Cost: 1.5
   */
  assertIndexInRange(i: UInt32 | number) {
    i = UInt32.from(i);
    if (!this._indicesInRange.has(i.value)) {
      assertLessThan16(i, this.length);
      this._indicesInRange.add(i.value);
    }
  }

  /**
   * Gets value at index i, and proves that the index is in the array.
   *
   * Handles constant indices without creating constraints.
   *
   * Cost: TN + 1.5
   */
  get(i: UInt32 | number): T {
    i = UInt32.from(i);
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
  getOption(i: UInt32 | number): Option<T> {
    i = UInt32.from(i);
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
    let NULL = ProvableType.synthesize(this.innerType);
    if (i.isConstant()) return this.array[Number(i)] ?? NULL;

    let type = this.innerType;
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
  set(i: UInt32 | number, value: T): void {
    i = UInt32.from(i);
    this.assertIndexInRange(i);
    this.setOrDoNothing(i.value, value);
  }

  /**
   * Sets a value at index i, or does nothing if the index is not in the array
   *
   * Cost: 1.5(T + 1)N
   */
  setOrDoNothing(i: Field, value: T): void {
    if (i.isConstant()) {
      let i0 = i.toBigInt();
      if (i0 < this.length) this.array[Number(i0)] = value;
      return;
    }
    zip(this.array, this._indexMask(i)).forEach(([t, equalsIJ], j) => {
      this.array[j] = Provable.if(equalsIJ, this.innerType, value, t);
    });
  }

  /**
   * Map every element of the array to a new value.
   */
  map<S>(type: ProvableType<S>, f: (t: T, i: number) => S): StaticArray<S> {
    let NewArray = StaticArray(type, this.length);
    let array = this.array.map(f);
    let newArray = new NewArray(array);

    // new array has same length, so it can use the same cached masks
    newArray._indexMasks = this._indexMasks;
    newArray._indicesInRange = this._indicesInRange;
    return newArray;
  }

  /**
   * Iterate over all elements of the array.
   */
  forEach(f: (t: T, i: number) => void) {
    this.array.forEach(f);
  }

  /**
   * Reduce the array to a single value.
   */
  reduce<S>(state: S, f: (state: S, t: T) => S): S {
    this.forEach((t) => {
      state = f(state, t);
    });
    return state;
  }

  /**
   * Split into a static number of fixed-size chunks.
   * Requires that the length is a multiple of the chunk size.
   */
  chunk(chunkSize: number) {
    let chunked = chunk(this.array, chunkSize);
    let newLength = this.length / chunkSize;
    const Chunk = StaticArray(this.innerType, chunkSize);
    const Chunked = StaticArray(Chunk, newLength);
    return new Chunked(chunked.map(Chunk.from));
  }

  /**
   * Reverse the array.
   *
   * Returns a copy and does not modify the original array.
   */
  toReversed() {
    return new (this.constructor as typeof StaticArrayBase<T, V>)(
      this.array.toReversed()
    );
  }

  slice(start: number, end: number) {
    assert(start >= 0, 'start must be >= 0');
    assert(end <= this.length, 'end must be <= length');
    const Array = StaticArray(this.innerType, end - start);
    return new Array(this.array.slice(start, end));
  }

  // cached variables to not duplicate constraints if we do something like array.get(i), array.set(i, ..) on the same index
  _indexMasks: Map<Field, Bool[]> = new Map();
  _indicesInRange: Set<Field> = new Set();

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

  toValue() {
    assertHasProperty(this.constructor, 'provable', 'Need subclass');
    return (this.constructor.provable as Provable<this, V[]>).toValue(this);
  }
}

/**
 * Base class of all StaticArray subclasses
 */
StaticArray.Base = StaticArrayBase;

type ProvableArray<T, V> = ProvableHashable<StaticArrayBase<T, V>, V[]> & {
  fromValue(array: (V | T)[] | StaticArrayBase<T>): StaticArrayBase<T, V>;
};
