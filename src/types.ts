export type { Tuple, ExcludeFromRecord, Constructor, JSONValue };

type Tuple<T = any> = [T, ...T[]] | [];

type ExcludeFromRecord<T, E> = {
  [P in keyof T as T[P] extends E ? never : P]: T[P];
};

type Constructor<T = any> = new (...args: any) => T;

type JSONValue =
  | string
  | number
  | boolean
  | null
  | JSONValue[]
  | { [key: string]: JSONValue };
