export type { Tuple, ExcludeFromRecord, Constructor, Json };

type Tuple<T = any> = [T, ...T[]] | [];

type ExcludeFromRecord<T, E> = {
  [P in keyof T as T[P] extends E ? never : P]: T[P];
};

type Constructor<T = any> = new (...args: any) => T;

type Literal = string | number | boolean | null;
type Json = Literal | { [key: string]: Json } | Json[];
