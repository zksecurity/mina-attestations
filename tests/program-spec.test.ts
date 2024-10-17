import { test } from 'node:test';
import assert from 'node:assert';
import { Bool, Bytes, Field, Poseidon, UInt32, UInt64, UInt8 } from 'o1js';
import {
  Spec,
  Input,
  Operation,
  Node,
  type UserInputs,
  splitUserInputs,
  recombineDataInputs,
  type DataInputs,
} from '../src/program-spec.ts';
import { createSignatureCredential, owner } from './test-utils.ts';
import { Credential, type CredentialOutputs } from '../src/credentials.ts';

function cred<D>(data: D): Credential<D> {
  return { owner, data };
}

test(' Spec and Node operations', async (t) => {
  const Bytes32 = Bytes(32);

  await t.test('Basic Spec with equality check', () => {
    const InputData = { age: Field };
    const spec = Spec(
      {
        data: Credential.none(InputData),
        targetAge: Input.claim(Field),
      },
      ({ data, targetAge }) => ({
        assert: Operation.equals(Operation.property(data, 'age'), targetAge),
        data: Operation.property(data, 'age'),
      })
    );

    const root: DataInputs<typeof spec.inputs> = {
      data: cred({ age: Field(25) }),
      targetAge: Field(25),
    };

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Field(25));
  });

  const data: Credential<{ age: Field; name: Bytes }> = cred({
    age: Field(30),
    name: Bytes32.fromString('Alice'),
  });

  await t.test('Spec with multiple assertions - and', () => {
    const InputData = { age: Field, name: Bytes32 };
    const spec = Spec(
      {
        data: Credential.none(InputData),
        targetAge: Input.claim(Field),
        targetName: Input.claim(Bytes32),
      },
      ({ data, targetAge, targetName }) => ({
        assert: Operation.and(
          Operation.equals(Operation.property(data, 'age'), targetAge),
          Operation.equals(Operation.property(data, 'name'), targetName)
        ),
        data: Operation.property(data, 'age'),
      })
    );

    const root: DataInputs<typeof spec.inputs> = {
      data,
      targetAge: Field(30),
      targetName: Bytes32.fromString('Alice'),
    };

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Field(30));
  });

  await t.test('Spec with multiple assertions - or - both are true', () => {
    const InputData = { age: Field, name: Bytes32 };
    const spec = Spec(
      {
        data: Credential.none(InputData),
        targetAge: Input.claim(Field),
        targetName: Input.claim(Bytes32),
      },
      ({ data, targetAge, targetName }) => ({
        assert: Operation.or(
          Operation.equals(Operation.property(data, 'age'), targetAge),
          Operation.equals(Operation.property(data, 'name'), targetName)
        ),
        data: Operation.property(data, 'age'),
      })
    );

    const root: DataInputs<typeof spec.inputs> = {
      data,
      targetAge: Field(30),
      targetName: Bytes32.fromString('Alice'),
    };

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Field(30));
  });

  await t.test('Spec with multiple assertions - or - only left is true', () => {
    const InputData = { age: Field, name: Bytes32 };
    const spec = Spec(
      {
        data: Credential.none(InputData),
        targetAge: Input.claim(Field),
        targetName: Input.claim(Bytes32),
      },
      ({ data, targetAge, targetName }) => ({
        assert: Operation.or(
          Operation.equals(Operation.property(data, 'age'), targetAge),
          Operation.equals(Operation.property(data, 'name'), targetName)
        ),
        data: Operation.property(data, 'age'),
      })
    );

    const root: DataInputs<typeof spec.inputs> = {
      data,
      targetAge: Field(30),
      targetName: Bytes32.fromString('Bob'),
    };

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Field(30));
  });

  await t.test(
    'Spec with multiple assertions - or - only right is true',
    () => {
      const InputData = { age: Field, name: Bytes32 };
      const spec = Spec(
        {
          data: Credential.none(InputData),
          targetAge: Input.claim(Field),
          targetName: Input.claim(Bytes32),
        },
        ({ data, targetAge, targetName }) => ({
          assert: Operation.or(
            Operation.equals(Operation.property(data, 'age'), targetAge),
            Operation.equals(Operation.property(data, 'name'), targetName)
          ),
          data: Operation.property(data, 'age'),
        })
      );
      const root: DataInputs<typeof spec.inputs> = {
        data: cred({ age: Field(11), name: Bytes32.fromString('Alice') }),
        targetAge: Field(30),
        targetName: Bytes32.fromString('Alice'),
      };

      const assertResult = Node.eval(root, spec.logic.assert);
      const dataResult = Node.eval(root, spec.logic.data);

      assert.strictEqual(assertResult.toBoolean(), true);
      assert.deepStrictEqual(dataResult, Field(11));
    }
  );

  await t.test('Spec with multiple assertions - not', () => {
    const InputData = { age: Field, name: Bytes32 };
    const spec = Spec(
      {
        data: Credential.none(InputData),
        targetAge: Input.claim(Field),
        targetName: Input.claim(Bytes32),
      },
      ({ data, targetAge, targetName }) => ({
        assert: Operation.and(
          Operation.not(
            Operation.equals(Operation.property(data, 'age'), targetAge)
          ),
          Operation.equals(Operation.property(data, 'name'), targetName)
        ),
        data: Operation.property(data, 'age'),
      })
    );

    const root: DataInputs<typeof spec.inputs> = {
      data: cred({ age: Field(11), name: Bytes32.fromString('Alice') }),
      targetAge: Field(30),
      targetName: Bytes32.fromString('Alice'),
    };

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Field(11));
  });

  await t.test('Spec with hash operation and equality check', () => {
    const InputData = { value: Field };
    const spec = Spec(
      {
        data: Credential.none(InputData),
        expectedHash: Input.claim(Field),
      },
      ({ data, expectedHash }) => ({
        assert: Operation.equals(
          Operation.hash(Operation.property(data, 'value')),
          expectedHash
        ),
        data: Operation.property(data, 'value'),
      })
    );

    const inputValue = Field(123456);
    const expectedHashValue = Poseidon.hash([inputValue]);

    const root: DataInputs<typeof spec.inputs> = {
      data: cred({ value: inputValue }),
      expectedHash: expectedHashValue,
    };

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, inputValue);
  });

  await t.test('Spec with multiple assertions and lessThan', () => {
    const InputData = { age: Field, name: Bytes32 };
    const spec = Spec(
      {
        data: Credential.none(InputData),
        targetAge: Input.claim(Field),
        targetName: Input.claim(Bytes32),
      },
      ({ data, targetAge, targetName }) => ({
        assert: Operation.and(
          Operation.lessThan(targetAge, Operation.property(data, 'age')),
          Operation.equals(Operation.property(data, 'name'), targetName)
        ),
        data: Operation.property(data, 'age'),
      })
    );

    const root: DataInputs<typeof spec.inputs> = {
      data: cred({ age: Field(30), name: Bytes32.fromString('Alice') }),
      targetAge: Field(18),
      targetName: Bytes32.fromString('Alice'),
    };

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Field(30));
  });

  await t.test('Spec with multiple assertions and lessThanEq', () => {
    const InputData = { age: Field, name: Bytes32 };
    const spec = Spec(
      {
        data: Credential.none(InputData),
        targetAge: Input.claim(Field),
        targetName: Input.claim(Bytes32),
      },
      ({ data, targetAge, targetName }) => ({
        assert: Operation.and(
          Operation.lessThanEq(Operation.property(data, 'age'), targetAge),
          Operation.equals(Operation.property(data, 'name'), targetName)
        ),
        data: Operation.property(data, 'age'),
      })
    );

    const root: DataInputs<typeof spec.inputs> = {
      data: cred({ age: Field(30), name: Bytes32.fromString('Alice') }),
      targetAge: Field(30),
      targetName: Bytes32.fromString('Alice'),
    };

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Field(30));
  });

  await t.test('Spec with add UInt32 and UInt64', () => {
    const spec = Spec(
      {
        value1: Credential.none(UInt32),
        value2: Credential.none(UInt64),
        sum: Input.claim(UInt64),
      },
      ({ value1, value2, sum }) => ({
        assert: Operation.equals(Operation.add(value1, value2), sum),
        data: Operation.add(value1, value2),
      })
    );

    const root: DataInputs<typeof spec.inputs> = {
      value1: cred(UInt32.from(1000000)),
      value2: cred(UInt64.from(1000000)),
      sum: UInt64.from(2000000),
    };

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, UInt64.from(2000000));
  });

  await t.test('Spec with sub UInt32 and UInt8', () => {
    const spec = Spec(
      {
        value1: Credential.none(UInt32),
        value2: Credential.none(UInt8),
        difference: Input.claim(UInt32),
      },
      ({ value1, value2, difference }) => ({
        assert: Operation.equals(Operation.sub(value1, value2), difference),
        data: Operation.sub(value1, value2),
      })
    );

    const root: DataInputs<typeof spec.inputs> = {
      value1: cred(UInt32.from(1000)),
      value2: cred(UInt8.from(200)),
      difference: UInt32.from(800),
    };

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, UInt32.from(800));
  });

  await t.test('Spec with mul UInt32 and UInt64', () => {
    const spec = Spec(
      {
        value1: Credential.none(UInt32),
        value2: Credential.none(UInt64),
        product: Input.claim(UInt64),
      },
      ({ value1, value2, product }) => ({
        assert: Operation.equals(Operation.mul(value1, value2), product),
        data: Operation.mul(value1, value2),
      })
    );

    const root: DataInputs<typeof spec.inputs> = {
      value1: cred(UInt32.from(1000)),
      value2: cred(UInt64.from(2000)),
      product: UInt64.from(2000000),
    };

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, UInt64.from(2000000));
  });

  await t.test('Spec with div UInt64 and UInt32', () => {
    const spec = Spec(
      {
        value1: Credential.none(UInt64),
        value2: Credential.none(UInt32),
        quotient: Input.claim(UInt64),
      },
      ({ value1, value2, quotient }) => ({
        assert: Operation.equals(Operation.div(value1, value2), quotient),
        data: Operation.div(value1, value2),
      })
    );

    const root: DataInputs<typeof spec.inputs> = {
      value1: cred(UInt64.from(1000000)),
      value2: cred(UInt32.from(1000)),
      quotient: UInt64.from(1000),
    };

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, UInt64.from(1000));
  });

  await t.test('Spec with ifThenElse operation', () => {
    const InputData = { value: Field };
    const spec = Spec(
      {
        data: Credential.none(InputData),
        threshold: Input.claim(Field),
        zero: Input.constant(Field, Field(0)),
      },
      ({ data, threshold, zero }) => ({
        assert: Node.constant(Bool(true)),
        data: Operation.ifThenElse(
          Operation.lessThan(Operation.property(data, 'value'), threshold),
          zero,
          Operation.property(data, 'value')
        ),
      })
    );

    // value < threshold
    const root1 = {
      data: cred({ value: Field(5) }),
      threshold: Field(10),
      zero: Field(0),
    };

    const result1 = Node.eval(root1, spec.logic.data);
    assert.deepStrictEqual(result1, Field(0));

    // value >= threshold
    const root2 = {
      data: cred({ value: Field(15) }),
      threshold: Field(10),
      zero: Field(0),
    };

    const result2 = Node.eval(root2, spec.logic.data);
    assert.deepStrictEqual(result2, Field(15));
  });

  await t.test('Spec with ifThenElse in assert', () => {
    const InputData = { value: Field };
    const spec = Spec(
      {
        data: Credential.none(InputData),
        threshold: Input.claim(Field),
        lowLimit: Input.constant(Field, Field(10)),
        highLimit: Input.constant(Field, Field(20)),
      },
      ({ data, threshold, lowLimit, highLimit }) => ({
        assert: Operation.ifThenElse(
          Operation.lessThan(Operation.property(data, 'value'), threshold),
          Operation.lessThan(Operation.property(data, 'value'), lowLimit),
          Operation.not(
            Operation.lessThan(Operation.property(data, 'value'), highLimit)
          )
        ),
        data: Operation.property(data, 'value'),
      })
    );

    // value < threshold and < lowLimit (should pass)
    const root1 = {
      data: cred({ value: Field(5) }),
      threshold: Field(15),
      lowLimit: Field(10),
      highLimit: Field(20),
    };

    const assertResult1 = Node.eval(root1, spec.logic.assert);
    assert.strictEqual(assertResult1.toBoolean(), true);

    // value >= threshold and >= highLimit (should pass)
    const root2 = {
      data: cred({ value: Field(25) }),
      threshold: Field(15),
      lowLimit: Field(10),
      highLimit: Field(20),
    };

    const assertResult2 = Node.eval(root2, spec.logic.assert);
    assert.strictEqual(assertResult2.toBoolean(), true);

    // lowLimit <= value < threshold (should fail)
    const root3 = {
      data: cred({ value: Field(12) }),
      threshold: Field(15),
      lowLimit: Field(10),
      highLimit: Field(20),
    };

    const assertResult3 = Node.eval(root3, spec.logic.assert);
    assert.strictEqual(assertResult3.toBoolean(), false);

    // threshold <= value < highLimit (should fail)
    const root4 = {
      data: cred({ value: Field(18) }),
      threshold: Field(15),
      lowLimit: Field(10),
      highLimit: Field(20),
    };

    const assertResult4 = Node.eval(root4, spec.logic.assert);
    assert.strictEqual(assertResult4.toBoolean(), false);
  });

  await t.test('Spec with ifThenElse as part of a complex assert', () => {
    const InputData = { value: Field };
    const spec = Spec(
      {
        data: Credential.none(InputData),
        threshold: Input.claim(Field),
        lowLimit: Input.constant(Field, Field(10)),
        highLimit: Input.constant(Field, Field(20)),
      },
      ({ data, threshold, lowLimit, highLimit }) => ({
        assert: Operation.and(
          Operation.lessThan(lowLimit, Operation.property(data, 'value')),
          Operation.ifThenElse(
            Operation.lessThan(Operation.property(data, 'value'), threshold),
            Operation.lessThan(Operation.property(data, 'value'), highLimit),
            Operation.equals(Operation.property(data, 'value'), highLimit)
          )
        ),
        data: Operation.property(data, 'value'),
      })
    );

    // 10 < value < threshold < highLimit (should pass)
    const root1 = {
      data: cred({ value: Field(15) }),
      threshold: Field(18),
      lowLimit: Field(10),
      highLimit: Field(20),
    };

    const assertResult1 = Node.eval(root1, spec.logic.assert);
    assert.strictEqual(assertResult1.toBoolean(), true);

    // 10 < threshold <= value = highLimit (should pass)
    const root2 = {
      data: cred({ value: Field(20) }),
      threshold: Field(18),
      lowLimit: Field(10),
      highLimit: Field(20),
    };

    const assertResult2 = Node.eval(root2, spec.logic.assert);
    assert.strictEqual(assertResult2.toBoolean(), true);

    // value <= lowLimit (should fail)
    const root3 = {
      data: cred({ value: Field(10) }),
      threshold: Field(18),
      lowLimit: Field(10),
      highLimit: Field(20),
    };

    const assertResult3 = Node.eval(root3, spec.logic.assert);
    assert.strictEqual(assertResult3.toBoolean(), false);

    // 10 < threshold <= value < highLimit (should fail)
    const root4 = {
      data: cred({ value: Field(19) }),
      threshold: Field(18),
      lowLimit: Field(10),
      highLimit: Field(20),
    };

    const assertResult4 = Node.eval(root4, spec.logic.assert);
    assert.strictEqual(assertResult4.toBoolean(), false);
  });

  await t.test('Spec with nested properties', () => {
    const InputData = { age: Field, name: Bytes32 };
    const NestedInputData = { person: InputData, points: Field };

    const spec = Spec(
      {
        data: Credential.none(NestedInputData),
        targetAge: Input.claim(Field),
        targetPoints: Input.claim(Field),
      },
      ({ data, targetAge, targetPoints }) => ({
        assert: Operation.and(
          Operation.equals(
            Operation.property(Operation.property(data, 'person'), 'age'),
            targetAge
          ),
          Operation.equals(Operation.property(data, 'points'), targetPoints)
        ),
        data: Operation.property(Operation.property(data, 'person'), 'name'),
      })
    );

    const root: DataInputs<typeof spec.inputs> = {
      data: cred({
        person: { age: Field(25), name: Bytes32.fromString('Bob') },
        points: Field(100),
      }),
      targetAge: Field(25),
      targetPoints: Field(100),
    };

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Bytes32.fromString('Bob'));
  });

  await t.test('Spec with constant input', () => {
    const InputData = { age: Field, name: Bytes32 };
    const spec = Spec(
      {
        data: Credential.none(InputData),
        constAge: Input.constant(Field, Field(25)),
      },
      ({ data, constAge }) => ({
        assert: Operation.equals(Operation.property(data, 'age'), constAge),
        data: Operation.property(data, 'name'),
      })
    );

    const root: DataInputs<typeof spec.inputs> = {
      data: cred({ age: Field(25), name: Bytes32.fromString('Charlie') }),
      constAge: Field(25),
    };

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Bytes32.fromString('Charlie'));
  });

  await t.test('Spec with credential', () => {
    const InputData = { age: Field, name: Bytes32 };
    const spec = Spec(
      {
        signedData: Credential.signatureNative(InputData),
        targetAge: Input.claim(Field),
        targetName: Input.claim(Bytes32),
      },
      ({ signedData, targetAge, targetName }) => ({
        assert: Operation.and(
          Operation.equals(Operation.property(signedData, 'age'), targetAge),
          Operation.equals(Operation.property(signedData, 'name'), targetName)
        ),
        data: Operation.property(signedData, 'age'),
      })
    );

    const data = { age: Field(30), name: Bytes32.fromString('David') };
    const signedData = createSignatureCredential(InputData, data);

    let userInputs: UserInputs<typeof spec.inputs> = {
      context: Field(0),
      // TODO actual owner signature
      ownerSignature: signedData.private.issuerSignature,
      credentials: { signedData },
      claims: { targetAge: Field(30), targetName: Bytes32.fromString('David') },
    };

    let { privateInput, publicInput } = splitUserInputs(userInputs);

    const mockCredentialOutputs: CredentialOutputs = {
      owner: owner,
      credentials: [
        {
          credential: { owner, data },
          issuer: Field(1234),
        },
      ],
    };
    let root = recombineDataInputs(
      spec,
      publicInput,
      privateInput,
      mockCredentialOutputs
    );

    assert.deepStrictEqual(root, {
      signedData: { credential: cred(data), issuer: Field(1234) },
      targetAge: Field(30),
      targetName: Bytes32.fromString('David'),
      owner: owner,
    });

    const assertResult = Node.eval(root, spec.logic.assert);
    const dataResult = Node.eval(root, spec.logic.data);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Field(30));
  });
});
