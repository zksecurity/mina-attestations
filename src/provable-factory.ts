import type { ProvableType } from 'o1js';
import { assert, assertHasProperty, hasProperty } from './util.ts';
import type { z } from 'zod';

export { ProvableFactory, type SerializedFactory };

type Constructor<T = any> = new (...args: any) => T;
type ProvableConstructor<T = any, V = any> = Constructor<T> &
  ProvableType<T, V>;

/**
 * Standard interface for polymorphic provable type that can be serialized.
 */
type ProvableFactory<N extends string = string, T = any, V = any> = ((
  ...args: any
) => ProvableConstructor<T, V>) & {
  name: N;
  Base: Constructor<T>;
};

type Serializer<
  A extends ProvableConstructor = ProvableConstructor,
  S extends Serialized = Serialized,
  V = any
> = {
  typeSchema: z.ZodType<S>;
  valueSchema: z.ZodType<V>;
  typeToJSON(constructor: A): S;
  typeFromJSON(json: S): A;
  valueToJSON(type: A, value: InstanceType<A>): V;
  valueFromJSON(type: A, json: V): InstanceType<A>;
};

type SerializedFactory = {
  _type: string;
  _isFactory: true;
} & Serialized;

type Serialized = Record<string, any>;

type MapValue = { base: Constructor } & Serializer;
const factories = new Map<string, MapValue>();

const ProvableFactory = {
  register<A extends ProvableFactory, S extends Serialized, V>(
    name: string,
    factory: A,
    serialize: Serializer<ReturnType<A>, S, V>
  ) {
    assert(!factories.has(name), 'Factory already registered');
    factories.set(name, { base: factory.Base, ...serialize });
  },

  getRegistered(value: unknown) {
    let entry: [string, MapValue] | undefined;
    for (let [key, factory] of factories.entries()) {
      if (value instanceof factory.base) {
        entry = [key, factory];
      }
    }
    return entry;
  },

  tryToJSON(constructor: unknown): SerializedFactory | undefined {
    if (!hasProperty(constructor, 'prototype')) return undefined;
    let entry = ProvableFactory.getRegistered(constructor.prototype);
    if (entry === undefined) return undefined;
    let [key, factory] = entry;
    let json = factory.typeToJSON(constructor as any);
    return { _type: key, ...json, _isFactory: true as const };
  },

  tryValueToJSON(
    value: unknown
  ): (SerializedFactory & { value: any }) | undefined {
    let entry = ProvableFactory.getRegistered(value);
    if (entry === undefined) return undefined;
    let [key, factory] = entry;
    let serializedType = factory.typeToJSON(value!.constructor as any);
    return {
      _type: key,
      ...serializedType,
      value: factory.valueToJSON(value!.constructor as any, value),
      _isFactory: true as const,
    };
  },

  isSerialized(json: unknown): json is SerializedFactory {
    return hasProperty(json, '_isFactory') && json._isFactory === true;
  },

  fromJSON(json: unknown): Constructor & ProvableType {
    assertHasProperty(json, '_type');
    assert(typeof json._type === 'string', 'Invalid type');
    let factory = factories.get(json._type);
    assert(factory !== undefined, `Type '${json._type}' not registered`);
    let validated = factory.typeSchema.parse(json);
    return factory.typeFromJSON(validated);
  },

  valueFromJSON(json: unknown) {
    assertHasProperty(json, '_type');
    assert(typeof json._type === 'string', 'Invalid type');
    let factory = factories.get(json._type);
    assert(factory !== undefined, `Type '${json._type}' not registered`);
    let validated = factory.typeSchema.parse(json);
    let type = factory.typeFromJSON(validated);
    assertHasProperty(json, 'value');
    let value = factory.valueSchema.parse(json.value);
    return factory.valueFromJSON(type, value);
  },
};
