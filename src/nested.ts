/**
 * Allows us to represent nested Provable types, to save us from always having to
 * wrap types in `Struct` and similar.
 */
import {
  type InferProvable,
  Provable,
  type ProvableHashable,
  Struct,
} from 'o1js';
import { array, ProvableType } from './o1js-missing.ts';
import { assertIsObject } from './util.ts';

export { NestedProvable, inferNestedProvable };

export type { NestedProvableFor, InferNestedProvable };

const NestedProvable = {
  get: (<T>(type: NestedProvableFor<T>): Provable<T> => {
    return ProvableType.isProvableType(type)
      ? ProvableType.get(type)
      : Struct(type);
  }) as {
    <T>(type: NestedProvableFor<T>): ProvableHashable<T>;
    (type: NestedProvable): ProvableHashable<any>;
  },

  fromValue<T>(value: T): NestedProvableFor<T> {
    try {
      // case 1: value comes from a provable type
      return ProvableType.fromValue(value);
    } catch {
      // case 2: value is a record of values from provable types
      if (typeof value === 'string') return String as any;

      if (Array.isArray(value))
        return array(NestedProvable.fromValue(value[0]), value.length) as any;

      assertIsObject(value);
      return Object.fromEntries(
        Object.entries(value).map(([key, value]) => [
          key,
          NestedProvable.fromValue(value),
        ])
      ) as any;
    }
  },
};

function inferNestedProvable<Type extends NestedProvable>(
  type: Type
): NestedProvableFor<InferNestedProvable<Type>> {
  // TODO annoying that this cast doesn't work without overriding the type
  return type as any;
}

// TODO!! NestedProvable should accurately requre hashable type

type NestedProvable = ProvableType | { [key: string]: NestedProvable };

type NestedProvableFor<T> =
  | ProvableType<T>
  | { [K in keyof T & string]: NestedProvableFor<T[K]> };

type InferNestedProvable<A> = A extends ProvableType
  ? InferProvable<A>
  : A extends Record<string, NestedProvable>
  ? {
      [K in keyof A]: InferNestedProvable<A[K]>;
    }
  : never;
