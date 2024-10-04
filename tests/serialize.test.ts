import { test } from 'node:test';
import assert from 'node:assert';
import {
  Input,
  Attestation,
  Operation,
  Spec,
  Node,
} from '../src/program-config.ts';

import {
  serializeProvableType,
  serializeNestedProvableFor,
  convertNodeToSerializable,
  convertInputToSerializable,
  convertSpecToSerializable,
  serializeSpec,
} from '../src/serialize-spec.ts';
import {
  Bool,
  Bytes,
  Field,
  Provable,
  PublicKey,
  Signature,
  Struct,
  UInt32,
  UInt64,
  UInt8,
  VerificationKey,
} from 'o1js';

test('Serialize Inputs', async (t) => {
  await t.test('should serialize basic types correctly', () => {
    assert.deepStrictEqual(serializeProvableType(Field), { type: 'Field' });
    assert.deepStrictEqual(serializeProvableType(Bool), { type: 'Bool' });
    assert.deepStrictEqual(serializeProvableType(UInt8), { type: 'UInt8' });
    assert.deepStrictEqual(serializeProvableType(UInt32), { type: 'UInt32' });
    assert.deepStrictEqual(serializeProvableType(UInt64), { type: 'UInt64' });
    assert.deepStrictEqual(serializeProvableType(PublicKey), {
      type: 'PublicKey',
    });
    assert.deepStrictEqual(serializeProvableType(Signature), {
      type: 'Signature',
    });
  });

  await t.test('should serialize structs correctly', () => {
    // TODO: implement
  });

  await t.test('should serialize simple provable types (nested)', () => {
    assert.deepStrictEqual(serializeNestedProvableFor(Field), {
      type: 'Field',
    });
    assert.deepStrictEqual(serializeNestedProvableFor(Bool), { type: 'Bool' });
    assert.deepStrictEqual(serializeNestedProvableFor(UInt8), {
      type: 'UInt8',
    });
    assert.deepStrictEqual(serializeNestedProvableFor(UInt32), {
      type: 'UInt32',
    });
    assert.deepStrictEqual(serializeNestedProvableFor(UInt64), {
      type: 'UInt64',
    });
    assert.deepStrictEqual(serializeNestedProvableFor(PublicKey), {
      type: 'PublicKey',
    });
    assert.deepStrictEqual(serializeNestedProvableFor(Signature), {
      type: 'Signature',
    });
  });

  await t.test('should serialize nested objects with provable types', () => {
    const nestedType = {
      field: Field,
      nested: {
        uint: UInt32,
        bool: Bool,
      },
    };

    assert.deepStrictEqual(serializeNestedProvableFor(nestedType), {
      field: { type: 'Field' },
      nested: {
        bool: { type: 'Bool' },
        uint: { type: 'UInt32' },
      },
    });
  });

  await t.test('should serialize complex nested structures', () => {
    const complexType = {
      simpleField: Field,
      nestedObject: {
        publicKey: PublicKey,
        signature: Signature,
        deeplyNested: {
          bool: Bool,
          uint64: UInt64,
        },
      },
    };

    assert.deepStrictEqual(serializeNestedProvableFor(complexType), {
      simpleField: { type: 'Field' },
      nestedObject: {
        publicKey: { type: 'PublicKey' },
        signature: { type: 'Signature' },
        deeplyNested: {
          bool: { type: 'Bool' },
          uint64: { type: 'UInt64' },
        },
      },
    });
  });

  await t.test('should throw an error for unsupported types', () => {
    assert.throws(() => serializeNestedProvableFor('unsupported' as any), {
      name: 'Error',
      message: 'Unsupported type in NestedProvableFor: unsupported',
    });
  });
});

test('Serialize Nodes', async (t) => {
  await t.test('should serialize constant Node', () => {
    const constantNode: Node<Field> = { type: 'constant', data: Field(123) };

    const serialized = convertNodeToSerializable(constantNode);

    const expected = {
      type: 'constant',
      data: {
        type: 'Field',
        value: '123',
      },
    };

    assert.deepEqual(serialized, expected);
  });

  await t.test('should serialize root Node', () => {
    const rootNode: Node = {
      type: 'root',
      input: {
        age: Input.private(Field),
        isAdmin: Input.public(Bool),
      },
    };

    const serialized = convertNodeToSerializable(rootNode);

    const expected = {
      type: 'root',
      input: {
        age: { type: 'private', data: { type: 'Field' } },
        isAdmin: { type: 'public', data: { type: 'Bool' } },
      },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize propery Node', () => {
    const propertyNode: Node = {
      type: 'property',
      key: 'age',
      inner: {
        type: 'root',
        input: {
          age: Input.private(Field),
          isAdmin: Input.public(Bool),
        },
      },
    };

    const serialized = convertNodeToSerializable(propertyNode);

    const expected = {
      type: 'property',
      key: 'age',
      inner: {
        type: 'root',
        input: {
          age: { type: 'private', data: { type: 'Field' } },
          isAdmin: { type: 'public', data: { type: 'Bool' } },
        },
      },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize equals Node', () => {
    const equalsNode: Node<Bool> = Operation.equals(
      { type: 'constant', data: Field(10) },
      { type: 'constant', data: Field(10) }
    );

    const serialized = convertNodeToSerializable(equalsNode);

    const expected = {
      type: 'equals',
      left: { type: 'constant', data: { type: 'Field', value: '10' } },
      right: { type: 'constant', data: { type: 'Field', value: '10' } },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize lessThan Node', () => {
    const lessThanNode: Node<Bool> = Operation.lessThan(
      { type: 'constant', data: UInt32.from(5) },
      { type: 'constant', data: UInt32.from(10) }
    );

    const serialized = convertNodeToSerializable(lessThanNode);

    const expected = {
      type: 'lessThan',
      left: { type: 'constant', data: { type: 'UInt32', value: '5' } },
      right: { type: 'constant', data: { type: 'UInt32', value: '10' } },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize lessThanEq Node', () => {
    const lessThanEqNode: Node<Bool> = Operation.lessThanEq(
      { type: 'constant', data: UInt64.from(15) },
      { type: 'constant', data: UInt64.from(15) }
    );

    const serialized = convertNodeToSerializable(lessThanEqNode);

    const expected = {
      type: 'lessThanEq',
      left: { type: 'constant', data: { type: 'UInt64', value: '15' } },
      right: { type: 'constant', data: { type: 'UInt64', value: '15' } },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize and Node', () => {
    const andNode: Node<Bool> = Operation.and(
      { type: 'constant', data: Bool(true) },
      { type: 'constant', data: Bool(false) }
    );

    const serialized = convertNodeToSerializable(andNode);

    const expected = {
      type: 'and',
      left: { type: 'constant', data: { type: 'Bool', value: 'true' } },
      right: { type: 'constant', data: { type: 'Bool', value: 'false' } },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize nested Nodes', () => {
    const nestedNode: Node<Bool> = Operation.and(
      Operation.lessThan(
        { type: 'constant', data: Field(5) },
        { type: 'constant', data: Field(10) }
      ),
      Operation.equals(
        { type: 'constant', data: Bool(true) },
        { type: 'constant', data: Bool(true) }
      )
    );

    const serialized = convertNodeToSerializable(nestedNode);

    const expected = {
      type: 'and',
      left: {
        type: 'lessThan',
        left: { type: 'constant', data: { type: 'Field', value: '5' } },
        right: { type: 'constant', data: { type: 'Field', value: '10' } },
      },
      right: {
        type: 'equals',
        left: { type: 'constant', data: { type: 'Bool', value: 'true' } },
        right: { type: 'constant', data: { type: 'Bool', value: 'true' } },
      },
    };

    assert.deepStrictEqual(serialized, expected);
  });
});

test('convertInputToSerializable', async (t) => {
  await t.test('should serialize constant input', () => {
    const input = Input.constant(Field, Field(42));

    const serialized = convertInputToSerializable(input);

    const expected = {
      type: 'constant',
      data: { type: 'Field' },
      value: '42',
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize public input', () => {
    const input = Input.public(Field);

    const serialized = convertInputToSerializable(input);

    const expected = {
      type: 'public',
      data: { type: 'Field' },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize private input', () => {
    const input = Input.private(Field);

    const serialized = convertInputToSerializable(input);

    const expected = {
      type: 'private',
      data: { type: 'Field' },
    };
    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize attestation input', () => {
    const InputData = { age: Field, isAdmin: Bool };
    const input = Attestation.signature(InputData);

    const serialized = convertInputToSerializable(input);

    const expected = {
      type: 'attestation',
      id: 'native-signature',
      public: { type: 'PublicKey' },
      private: { type: 'Signature' },
      data: {
        age: { type: 'Field' },
        isAdmin: { type: 'Bool' },
      },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize nested input', () => {
    const NestedInputData = {
      personal: {
        age: Field,
        id: UInt64,
      },
      score: UInt32,
    };
    const input = Input.private(NestedInputData);

    const serialized = convertInputToSerializable(input);

    const expected = {
      type: 'private',
      data: {
        personal: {
          age: { type: 'Field' },
          id: { type: 'UInt64' },
        },
        score: { type: 'UInt32' },
      },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should throw error for unsupported input type', () => {
    const invalidInput = { type: 'invalid' } as any;
    assert.throws(() => convertInputToSerializable(invalidInput), {
      name: 'Error',
      message: 'Invalid input type',
    });
  });
});

test('convertSpecToSerializable', async (t) => {
  await t.test('should serialize a simple Spec', () => {
    const spec = Spec(
      {
        age: Input.private(Field),
        isAdmin: Input.public(Bool),
        maxAge: Input.constant(Field, Field(100)),
      },
      ({ age, isAdmin, maxAge }) => ({
        assert: Operation.and(Operation.lessThan(age, maxAge), isAdmin),
        data: age,
      })
    );

    const serialized = convertSpecToSerializable(spec);

    const expected = {
      inputs: {
        age: { type: 'private', data: { type: 'Field' } },
        isAdmin: { type: 'public', data: { type: 'Bool' } },
        maxAge: { type: 'constant', data: { type: 'Field' }, value: '100' },
      },
      logic: {
        assert: {
          type: 'and',
          left: {
            type: 'lessThan',
            left: {
              type: 'property',
              key: 'age',
              inner: {
                type: 'root',
                input: {
                  age: { type: 'private', data: { type: 'Field' } },
                  isAdmin: { type: 'public', data: { type: 'Bool' } },
                  maxAge: {
                    type: 'constant',
                    data: { type: 'Field' },
                    value: '100',
                  },
                },
              },
            },
            right: {
              type: 'property',
              key: 'maxAge',
              inner: {
                type: 'root',
                input: {
                  age: { type: 'private', data: { type: 'Field' } },
                  isAdmin: { type: 'public', data: { type: 'Bool' } },
                  maxAge: {
                    type: 'constant',
                    data: { type: 'Field' },
                    value: '100',
                  },
                },
              },
            },
          },
          right: {
            type: 'property',
            key: 'isAdmin',
            inner: {
              type: 'root',
              input: {
                age: { type: 'private', data: { type: 'Field' } },
                isAdmin: { type: 'public', data: { type: 'Bool' } },
                maxAge: {
                  type: 'constant',
                  data: { type: 'Field' },
                  value: '100',
                },
              },
            },
          },
        },
        data: {
          type: 'property',
          key: 'age',
          inner: {
            type: 'root',
            input: {
              age: { type: 'private', data: { type: 'Field' } },
              isAdmin: { type: 'public', data: { type: 'Bool' } },
              maxAge: {
                type: 'constant',
                data: { type: 'Field' },
                value: '100',
              },
            },
          },
        },
      },
    };

    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize a Spec with an attestation', () => {
    const spec = Spec(
      {
        signedData: Attestation.signature({ field: Field }),
        zeroField: Input.constant(Field, Field(0)),
      },
      ({ signedData, zeroField }) => ({
        assert: Operation.equals(
          Operation.property(signedData, 'field'),
          zeroField
        ),
        data: signedData,
      })
    );

    const serialized = convertSpecToSerializable(spec);
    const expected = {
      inputs: {
        signedData: {
          type: 'attestation',
          id: 'native-signature',
          public: { type: 'PublicKey' },
          private: { type: 'Signature' },
          data: {
            field: { type: 'Field' },
          },
        },
        zeroField: { type: 'constant', data: { type: 'Field' }, value: '0' },
      },
      logic: {
        assert: {
          type: 'equals',
          left: {
            type: 'property',
            key: 'field',
            inner: {
              type: 'property',
              key: 'signedData',
              inner: {
                type: 'root',
                input: {
                  signedData: {
                    type: 'attestation',
                    id: 'native-signature',
                    public: { type: 'PublicKey' },
                    private: { type: 'Signature' },
                    data: {
                      field: { type: 'Field' },
                    },
                  },
                  zeroField: {
                    type: 'constant',
                    data: { type: 'Field' },
                    value: '0',
                  },
                },
              },
            },
          },
          right: {
            type: 'property',
            key: 'zeroField',
            inner: {
              type: 'root',
              input: {
                signedData: {
                  type: 'attestation',
                  id: 'native-signature',
                  public: { type: 'PublicKey' },
                  private: { type: 'Signature' },
                  data: {
                    field: { type: 'Field' },
                  },
                },
                zeroField: {
                  type: 'constant',
                  data: { type: 'Field' },
                  value: '0',
                },
              },
            },
          },
        },
        data: {
          type: 'property',
          key: 'signedData',
          inner: {
            type: 'root',
            input: {
              signedData: {
                type: 'attestation',
                id: 'native-signature',
                public: { type: 'PublicKey' },
                private: { type: 'Signature' },
                data: {
                  field: { type: 'Field' },
                },
              },
              zeroField: {
                type: 'constant',
                data: { type: 'Field' },
                value: '0',
              },
            },
          },
        },
      },
    };
    assert.deepStrictEqual(serialized, expected);
  });

  await t.test('should serialize a Spec with nested operations', () => {
    const spec = Spec(
      {
        field1: Input.private(Field),
        field2: Input.private(Field),
        zeroField: Input.constant(Field, Field(0)),
      },
      ({ field1, field2, zeroField }) => ({
        assert: Operation.and(
          Operation.lessThan(field1, field2),
          Operation.equals(field1, zeroField)
        ),
        data: field2,
      })
    );

    const serialized = convertSpecToSerializable(spec);
    const expected = {
      inputs: {
        field1: { type: 'private', data: { type: 'Field' } },
        field2: { type: 'private', data: { type: 'Field' } },
        zeroField: { type: 'constant', data: { type: 'Field' }, value: '0' },
      },
      logic: {
        assert: {
          type: 'and',
          left: {
            type: 'lessThan',
            left: {
              type: 'property',
              key: 'field1',
              inner: {
                type: 'root',
                input: {
                  field1: { type: 'private', data: { type: 'Field' } },
                  field2: { type: 'private', data: { type: 'Field' } },
                  zeroField: {
                    type: 'constant',
                    data: { type: 'Field' },
                    value: '0',
                  },
                },
              },
            },
            right: {
              type: 'property',
              key: 'field2',
              inner: {
                type: 'root',
                input: {
                  field1: { type: 'private', data: { type: 'Field' } },
                  field2: { type: 'private', data: { type: 'Field' } },
                  zeroField: {
                    type: 'constant',
                    data: { type: 'Field' },
                    value: '0',
                  },
                },
              },
            },
          },
          right: {
            type: 'equals',
            left: {
              type: 'property',
              key: 'field1',
              inner: {
                type: 'root',
                input: {
                  field1: { type: 'private', data: { type: 'Field' } },
                  field2: { type: 'private', data: { type: 'Field' } },
                  zeroField: {
                    type: 'constant',
                    data: { type: 'Field' },
                    value: '0',
                  },
                },
              },
            },
            right: {
              type: 'property',
              key: 'zeroField',
              inner: {
                type: 'root',
                input: {
                  field1: { type: 'private', data: { type: 'Field' } },
                  field2: { type: 'private', data: { type: 'Field' } },
                  zeroField: {
                    type: 'constant',
                    data: { type: 'Field' },
                    value: '0',
                  },
                },
              },
            },
          },
        },
        data: {
          type: 'property',
          key: 'field2',
          inner: {
            type: 'root',
            input: {
              field1: { type: 'private', data: { type: 'Field' } },
              field2: { type: 'private', data: { type: 'Field' } },
              zeroField: {
                type: 'constant',
                data: { type: 'Field' },
                value: '0',
              },
            },
          },
        },
      },
    };
    assert.deepStrictEqual(serialized, expected);
  });
});
