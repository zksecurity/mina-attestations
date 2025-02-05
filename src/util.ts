export {
  assert,
  assertDefined,
  defined,
  Required,
  assertHasProperty,
  assertHasMethod,
  hasProperty,
  assertIsObject,
  notImplemented,
  zip,
  chunk,
  chunkString,
  pad,
  fill,
  arrayEqual,
  mapObject,
  mapToObject,
  mapEntries,
  zipObjects,
  assertExtendsShape,
  isSubclass,
  stringLength,
  mod,
  Bytes,
};

function assert(
  condition: boolean,
  message?: string | (() => string | undefined)
): asserts condition {
  if (!condition) {
    message = typeof message === 'function' ? message() : message;
    throw Error(message ?? 'Assertion failed');
  }
}

function assertDefined<T>(
  input: T | undefined,
  message?: string
): asserts input is T {
  if (input === undefined) {
    throw Error(message ?? 'Input is undefined');
  }
}

function defined<T>(input: T | undefined, message?: string): T {
  assertDefined(input, message);
  return input;
}

function Required<T extends {}>(
  t: T
): {
  [P in keyof T]-?: T[P];
} {
  return new Proxy(t, {
    get(target, key) {
      return defined(
        (target as any)[key],
        `Property "${String(key)}" is undefined`
      );
    },
  }) as Required<T>;
}

function assertIsObject(
  obj: unknown,
  message?: string
): asserts obj is object | Function {
  assert(
    (typeof obj === 'object' && obj !== null) || typeof obj === 'function',
    () => {
      // console.log('not an object:', obj);
      return message;
    }
  );
}

function assertHasProperty<K extends string>(
  obj: unknown,
  key: K,
  message?: string
): asserts obj is Record<K, unknown> {
  assertIsObject(obj, message ?? `Expected value to be an object or function`);
  assert(key in obj, message ?? `Expected object to have property ${key}`);
}

function assertHasMethod<K extends string>(
  obj: unknown,
  key: K,
  message?: string
): asserts obj is Record<K, Function> {
  assertHasProperty(obj, key, message);
  assert(typeof obj[key] === 'function', message);
}

function hasProperty<K extends string>(
  obj: unknown,
  key: K
): obj is Record<K, unknown> {
  return (
    ((typeof obj === 'object' && obj !== null) || typeof obj === 'function') &&
    key in obj
  );
}

function notImplemented(): never {
  throw Error('Not implemented');
}

function zip<T, S>(a: T[], b: S[]) {
  assert(a.length === b.length, 'zip(): arrays of unequal length');
  return a.map((a, i): [T, S] => [a, b[i]!]);
}

function chunk<T>(array: T[], size: number): T[][] {
  assert(
    array.length % size === 0,
    `${array.length} is not a multiple of ${size}`
  );
  return Array.from({ length: array.length / size }, (_, i) =>
    array.slice(size * i, size * (i + 1))
  );
}

function chunkString(str: string, size: number): string[] {
  return chunk([...str], size).map((chunk) => chunk.join(''));
}

function pad<T>(array: T[], size: number, value: T | (() => T)): T[] {
  assert(
    array.length <= size,
    `padding array of size ${array.length} larger than target size ${size}`
  );
  let cb: () => T =
    typeof value === 'function' ? (value as () => T) : () => value;
  return array.concat(Array.from({ length: size - array.length }, cb));
}

function fill<T>(size: number, value: T | (() => T)): T[] {
  let cb: () => T =
    typeof value === 'function' ? (value as () => T) : () => value;
  return Array.from({ length: size }, cb);
}

function arrayEqual(
  aI: unknown[] | Uint8Array | ArrayBuffer,
  bI: unknown[] | Uint8Array | ArrayBuffer
): boolean {
  let a = aI instanceof ArrayBuffer ? new Uint8Array(aI) : aI;
  let b = bI instanceof ArrayBuffer ? new Uint8Array(bI) : bI;
  let n = a.length;
  if (n !== b.length) return false;
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function mapObject<
  T extends Record<string, any>,
  S extends Record<keyof T, any>
>(obj: T, fn: <K extends keyof T>(value: T[K], key: K) => S[K]): S {
  let result = {} as S;
  for (let key in obj) {
    result[key] = fn(obj[key], key);
  }
  return result;
}

function mapToObject<
  Key extends string | number | symbol,
  F extends <K extends Key>(key: K, i: number) => any
>(keys: Key[], fn: F) {
  let s = {} as { [K in Key]: ReturnType<F> };
  keys.forEach((key, i) => {
    s[key] = fn(key, i);
  });
  return s;
}

function zipObjects<
  T extends Record<string, any>,
  S extends Record<keyof T, any>
>(t: T, s: S) {
  assertExtendsShape(t, s);
  assertExtendsShape(s, t);
  return mapObject<T, { [K in keyof T]: [T[K], S[K]] }>(t, (t, key) => [
    t,
    s[key],
  ]);
}

function mapEntries<T extends Record<string, any>, S>(
  obj: T,
  fn: (key: keyof T & string, value: T[keyof T & string]) => S
): S[] {
  return Object.entries(obj).map((entry) => fn(...entry));
}

function assertExtendsShape<B extends Record<string, any>>(
  a: object,
  b: B
): asserts a is Record<keyof B, any> {
  for (let key in b) {
    if (!(key in a)) throw Error(`Expected object to have property ${key}`);
  }
}

type Constructor<T> = new (...args: any) => T;

function isSubclass<B extends Constructor<any>>(
  constructor: unknown,
  base: B
): constructor is B {
  if (typeof constructor !== 'function') return false;
  if (!hasProperty(constructor, 'prototype')) return false;
  return constructor.prototype instanceof base;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

function stringLength(str: string): number {
  return enc.encode(str).length;
}

// modulo that properly handles negative numbers
function mod(x: bigint, p: bigint): bigint {
  let z = x % p;
  return z < 0 ? z + p : z;
}

const Bytes = {
  fromString(str: string) {
    return enc.encode(str);
  },
  toString(bytes: Uint8Array) {
    return dec.decode(bytes);
  },

  fromHex(hex: string) {
    if (hex.startsWith('0x')) hex = hex.slice(2);
    let bytes = chunkString(hex, 2).map((byte) => parseInt(byte, 16));
    return new Uint8Array(bytes);
  },
  toHex(bytes: Uint8Array) {
    return bytes.reduce(
      (hex, byte) => hex + byte.toString(16).padStart(2, '0'),
      ''
    );
  },

  padStart(bytes: Uint8Array, size: number, value: number): Uint8Array {
    assert(bytes.length <= size, 'Bytes.padStart(): bytes larger than size');
    if (bytes.length === size) return bytes;
    let a = new Uint8Array(size);
    a.fill(value, 0, size - bytes.length);
    a.set(bytes, size - bytes.length);
    return a;
  },

  padEnd(bytes: Uint8Array, size: number, value: number): Uint8Array {
    assert(bytes.length <= size, 'Bytes.padEnd(): bytes larger than size');
    if (bytes.length === size) return bytes;
    let a = new Uint8Array(size);
    a.set(bytes);
    a.fill(value, bytes.length);
    return a;
  },

  concat(...arrays: Uint8Array[]): Uint8Array {
    let size = arrays.reduce((s, a) => s + a.length, 0);
    let a = new Uint8Array(size);
    let offset = 0;
    arrays.forEach((b) => {
      a.set(b, offset);
      offset += b.length;
    });
    return a;
  },
};
