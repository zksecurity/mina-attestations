import { test } from 'node:test';
import assert from 'node:assert';
import { Bool, Bytes, Field, Signature, UInt32, UInt64, UInt8 } from 'o1js';
import {
  Spec,
  type UserInputs,
  splitUserInputs,
  rootValue,
  type RootValue,
  Claim,
  Constant,
} from '../src/program-spec.ts';
import { issuerKey, owner } from './test-utils.ts';
import {
  unsafeMissingOwner,
  type CredentialOutputs,
} from '../src/credential.ts';
import { Credential } from '../src/credential-index.ts';
import { hashDynamic, Operation } from '../src/index.ts';
import { Node } from '../src/operation.ts';

function cred<D>(data: D) {
  return { data, issuer: Field(0), witness: undefined };
}

test('Spec and Node operations', async (t) => {
  const Bytes32 = Bytes(32);

  await t.test('Basic Spec with equality check', () => {
    const InputData = { age: Field };
    const spec = Spec(
      {
        data: Credential.Unsigned(InputData),
        targetAge: Claim(Field),
      },
      ({ data, targetAge }) => ({
        assert: Operation.equals(Operation.property(data, 'age'), targetAge),
        outputClaim: Operation.property(data, 'age'),
      })
    );

    const root: RootValue<typeof spec.inputs> = {
      owner: unsafeMissingOwner(),
      data: cred({ age: Field(25) }),
      targetAge: Field(25),
    };

    const assertResult = Node.eval(root, spec.assert);
    const dataResult = Node.eval(root, spec.outputClaim);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Field(25));
  });

  const data = cred({
    age: Field(30),
    name: Bytes32.fromString('Alice'),
  });

  await t.test('Spec with multiple assertions - and', () => {
    const InputData = { age: Field, name: Bytes32 };
    const spec = Spec(
      {
        data: Credential.Unsigned(InputData),
        targetAge: Claim(Field),
        targetName: Claim(Bytes32),
      },
      ({ data, targetAge, targetName }) => ({
        assert: Operation.and(
          Operation.equals(Operation.property(data, 'age'), targetAge),
          Operation.equals(Operation.property(data, 'name'), targetName)
        ),
        outputClaim: Operation.property(data, 'age'),
      })
    );

    const root: RootValue<typeof spec.inputs> = {
      owner: unsafeMissingOwner(),
      data,
      targetAge: Field(30),
      targetName: Bytes32.fromString('Alice'),
    };

    const assertResult = Node.eval(root, spec.assert);
    const dataResult = Node.eval(root, spec.outputClaim);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Field(30));
  });

  await t.test('Spec with multiple assertions - or - both are true', () => {
    const InputData = { age: Field, name: Bytes32 };
    const spec = Spec(
      {
        data: Credential.Unsigned(InputData),
        targetAge: Claim(Field),
        targetName: Claim(Bytes32),
      },
      ({ data, targetAge, targetName }) => ({
        assert: Operation.or(
          Operation.equals(Operation.property(data, 'age'), targetAge),
          Operation.equals(Operation.property(data, 'name'), targetName)
        ),
        outputClaim: Operation.property(data, 'age'),
      })
    );

    const root: RootValue<typeof spec.inputs> = {
      owner: unsafeMissingOwner(),
      data,
      targetAge: Field(30),
      targetName: Bytes32.fromString('Alice'),
    };

    const assertResult = Node.eval(root, spec.assert);
    const dataResult = Node.eval(root, spec.outputClaim);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Field(30));
  });

  await t.test('Spec with multiple assertions - or - only left is true', () => {
    const InputData = { age: Field, name: Bytes32 };
    const spec = Spec(
      {
        data: Credential.Unsigned(InputData),
        targetAge: Claim(Field),
        targetName: Claim(Bytes32),
      },
      ({ data, targetAge, targetName }) => ({
        assert: Operation.or(
          Operation.equals(Operation.property(data, 'age'), targetAge),
          Operation.equals(Operation.property(data, 'name'), targetName)
        ),
        outputClaim: Operation.property(data, 'age'),
      })
    );

    const root: RootValue<typeof spec.inputs> = {
      owner: unsafeMissingOwner(),
      data,
      targetAge: Field(30),
      targetName: Bytes32.fromString('Bob'),
    };

    const assertResult = Node.eval(root, spec.assert);
    const dataResult = Node.eval(root, spec.outputClaim);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Field(30));
  });

  await t.test(
    'Spec with multiple assertions - or - only right is true',
    () => {
      const InputData = { age: Field, name: Bytes32 };
      const spec = Spec(
        {
          data: Credential.Unsigned(InputData),
          targetAge: Claim(Field),
          targetName: Claim(Bytes32),
        },
        ({ data, targetAge, targetName }) => ({
          assert: Operation.or(
            Operation.equals(Operation.property(data, 'age'), targetAge),
            Operation.equals(Operation.property(data, 'name'), targetName)
          ),
          outputClaim: Operation.property(data, 'age'),
        })
      );
      const root: RootValue<typeof spec.inputs> = {
        owner: unsafeMissingOwner(),
        data: cred({ age: Field(11), name: Bytes32.fromString('Alice') }),
        targetAge: Field(30),
        targetName: Bytes32.fromString('Alice'),
      };

      const assertResult = Node.eval(root, spec.assert);
      const dataResult = Node.eval(root, spec.outputClaim);

      assert.strictEqual(assertResult.toBoolean(), true);
      assert.deepStrictEqual(dataResult, Field(11));
    }
  );

  await t.test('Spec with multiple assertions - not', () => {
    const InputData = { age: Field, name: Bytes32 };
    const spec = Spec(
      {
        data: Credential.Unsigned(InputData),
        targetAge: Claim(Field),
        targetName: Claim(Bytes32),
      },
      ({ data, targetAge, targetName }) => ({
        assert: Operation.and(
          Operation.not(
            Operation.equals(Operation.property(data, 'age'), targetAge)
          ),
          Operation.equals(Operation.property(data, 'name'), targetName)
        ),
        outputClaim: Operation.property(data, 'age'),
      })
    );

    const root: RootValue<typeof spec.inputs> = {
      owner: unsafeMissingOwner(),
      data: cred({ age: Field(11), name: Bytes32.fromString('Alice') }),
      targetAge: Field(30),
      targetName: Bytes32.fromString('Alice'),
    };

    const assertResult = Node.eval(root, spec.assert);
    const dataResult = Node.eval(root, spec.outputClaim);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Field(11));
  });

  await t.test('Spec with hash operation and equality check', () => {
    const InputData = { value: Field };
    const spec = Spec(
      {
        data: Credential.Unsigned(InputData),
        expectedHash: Claim(Field),
      },
      ({ data, expectedHash }) => ({
        assert: Operation.equals(
          Operation.hash(Operation.property(data, 'value')),
          expectedHash
        ),
        outputClaim: Operation.property(data, 'value'),
      })
    );

    const inputValue = Field(123456);
    const expectedHashValue = hashDynamic(inputValue);

    const root: RootValue<typeof spec.inputs> = {
      owner: unsafeMissingOwner(),
      data: cred({ value: inputValue }),
      expectedHash: expectedHashValue,
    };

    const assertResult = Node.eval(root, spec.assert);
    const dataResult = Node.eval(root, spec.outputClaim);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, inputValue);
  });

  await t.test('Spec with multiple assertions and lessThan', () => {
    const InputData = { age: Field, name: Bytes32 };
    const spec = Spec(
      {
        data: Credential.Unsigned(InputData),
        targetAge: Claim(Field),
        targetName: Claim(Bytes32),
      },
      ({ data, targetAge, targetName }) => ({
        assert: Operation.and(
          Operation.lessThan(targetAge, Operation.property(data, 'age')),
          Operation.equals(Operation.property(data, 'name'), targetName)
        ),
        outputClaim: Operation.property(data, 'age'),
      })
    );

    const root: RootValue<typeof spec.inputs> = {
      owner: unsafeMissingOwner(),
      data: cred({ age: Field(30), name: Bytes32.fromString('Alice') }),
      targetAge: Field(18),
      targetName: Bytes32.fromString('Alice'),
    };

    const assertResult = Node.eval(root, spec.assert);
    const dataResult = Node.eval(root, spec.outputClaim);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Field(30));
  });

  await t.test('Spec with multiple assertions and lessThanEq', () => {
    const InputData = { age: Field, name: Bytes32 };
    const spec = Spec(
      {
        data: Credential.Unsigned(InputData),
        targetAge: Claim(Field),
        targetName: Claim(Bytes32),
      },
      ({ data, targetAge, targetName }) => ({
        assert: Operation.and(
          Operation.lessThanEq(Operation.property(data, 'age'), targetAge),
          Operation.equals(Operation.property(data, 'name'), targetName)
        ),
        outputClaim: Operation.property(data, 'age'),
      })
    );

    const root: RootValue<typeof spec.inputs> = {
      owner: unsafeMissingOwner(),
      data: cred({ age: Field(30), name: Bytes32.fromString('Alice') }),
      targetAge: Field(30),
      targetName: Bytes32.fromString('Alice'),
    };

    const assertResult = Node.eval(root, spec.assert);
    const dataResult = Node.eval(root, spec.outputClaim);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Field(30));
  });

  await t.test('Spec with add UInt32 and UInt64', () => {
    const spec = Spec(
      {
        value1: Credential.Unsigned(UInt32),
        value2: Credential.Unsigned(UInt64),
        sum: Claim(UInt64),
      },
      ({ value1, value2, sum }) => ({
        assert: Operation.equals(Operation.add(value1, value2), sum),
        outputClaim: Operation.add(value1, value2),
      })
    );

    const root: RootValue<typeof spec.inputs> = {
      owner: unsafeMissingOwner(),
      value1: cred(UInt32.from(1000000)),
      value2: cred(UInt64.from(1000000)),
      sum: UInt64.from(2000000),
    };

    const assertResult = Node.eval(root, spec.assert);
    const dataResult = Node.eval(root, spec.outputClaim);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, UInt64.from(2000000));
  });

  await t.test('Spec with sub UInt32 and UInt8', () => {
    const spec = Spec(
      {
        value1: Credential.Unsigned(UInt32),
        value2: Credential.Unsigned(UInt8),
        difference: Claim(UInt32),
      },
      ({ value1, value2, difference }) => ({
        assert: Operation.equals(Operation.sub(value1, value2), difference),
        outputClaim: Operation.sub(value1, value2),
      })
    );

    const root: RootValue<typeof spec.inputs> = {
      owner: unsafeMissingOwner(),
      value1: cred(UInt32.from(1000)),
      value2: cred(UInt8.from(200)),
      difference: UInt32.from(800),
    };

    const assertResult = Node.eval(root, spec.assert);
    const dataResult = Node.eval(root, spec.outputClaim);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, UInt32.from(800));
  });

  await t.test('Spec with mul UInt32 and UInt64', () => {
    const spec = Spec(
      {
        value1: Credential.Unsigned(UInt32),
        value2: Credential.Unsigned(UInt64),
        product: Claim(UInt64),
      },
      ({ value1, value2, product }) => ({
        assert: Operation.equals(Operation.mul(value1, value2), product),
        outputClaim: Operation.mul(value1, value2),
      })
    );

    const root: RootValue<typeof spec.inputs> = {
      owner: unsafeMissingOwner(),
      value1: cred(UInt32.from(1000)),
      value2: cred(UInt64.from(2000)),
      product: UInt64.from(2000000),
    };

    const assertResult = Node.eval(root, spec.assert);
    const dataResult = Node.eval(root, spec.outputClaim);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, UInt64.from(2000000));
  });

  await t.test('Spec with div UInt64 and UInt32', () => {
    const spec = Spec(
      {
        value1: Credential.Unsigned(UInt64),
        value2: Credential.Unsigned(UInt32),
        quotient: Claim(UInt64),
      },
      ({ value1, value2, quotient }) => ({
        assert: Operation.equals(Operation.div(value1, value2), quotient),
        outputClaim: Operation.div(value1, value2),
      })
    );

    const root: RootValue<typeof spec.inputs> = {
      owner: unsafeMissingOwner(),
      value1: cred(UInt64.from(1000000)),
      value2: cred(UInt32.from(1000)),
      quotient: UInt64.from(1000),
    };

    const assertResult = Node.eval(root, spec.assert);
    const dataResult = Node.eval(root, spec.outputClaim);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, UInt64.from(1000));
  });

  await t.test('Spec with ifThenElse operation', () => {
    const InputData = { value: Field };
    const spec = Spec(
      {
        data: Credential.Unsigned(InputData),
        threshold: Claim(Field),
        zero: Constant(Field, Field(0)),
      },
      ({ data, threshold, zero }) => ({
        assert: Operation.constant(Bool(true)),
        outputClaim: Operation.ifThenElse(
          Operation.lessThan(Operation.property(data, 'value'), threshold),
          zero,
          Operation.property(data, 'value')
        ),
      })
    );

    // value < threshold
    const root1 = {
      owner: unsafeMissingOwner(),
      data: cred({ value: Field(5) }),
      threshold: Field(10),
      zero: Field(0),
    };

    const result1 = Node.eval(root1, spec.outputClaim);
    assert.deepStrictEqual(result1, Field(0));

    // value >= threshold
    const root2 = {
      owner: unsafeMissingOwner(),
      data: cred({ value: Field(15) }),
      threshold: Field(10),
      zero: Field(0),
    };

    const result2 = Node.eval(root2, spec.outputClaim);
    assert.deepStrictEqual(result2, Field(15));
  });

  await t.test('Spec with ifThenElse in assert', () => {
    const InputData = { value: Field };
    const spec = Spec(
      {
        data: Credential.Unsigned(InputData),
        threshold: Claim(Field),
        lowLimit: Constant(Field, Field(10)),
        highLimit: Constant(Field, Field(20)),
      },
      ({ data, threshold, lowLimit, highLimit }) => ({
        assert: Operation.ifThenElse(
          Operation.lessThan(Operation.property(data, 'value'), threshold),
          Operation.lessThan(Operation.property(data, 'value'), lowLimit),
          Operation.not(
            Operation.lessThan(Operation.property(data, 'value'), highLimit)
          )
        ),
        outputClaim: Operation.property(data, 'value'),
      })
    );

    // value < threshold and < lowLimit (should pass)
    const root1 = {
      owner: unsafeMissingOwner(),
      data: cred({ value: Field(5) }),
      threshold: Field(15),
      lowLimit: Field(10),
      highLimit: Field(20),
    };

    const assertResult1 = Node.eval(root1, spec.assert);
    assert.strictEqual(assertResult1.toBoolean(), true);

    // value >= threshold and >= highLimit (should pass)
    const root2 = {
      owner: unsafeMissingOwner(),
      data: cred({ value: Field(25) }),
      threshold: Field(15),
      lowLimit: Field(10),
      highLimit: Field(20),
    };

    const assertResult2 = Node.eval(root2, spec.assert);
    assert.strictEqual(assertResult2.toBoolean(), true);

    // lowLimit <= value < threshold (should fail)
    const root3 = {
      owner: unsafeMissingOwner(),
      data: cred({ value: Field(12) }),
      threshold: Field(15),
      lowLimit: Field(10),
      highLimit: Field(20),
    };

    const assertResult3 = Node.eval(root3, spec.assert);
    assert.strictEqual(assertResult3.toBoolean(), false);

    // threshold <= value < highLimit (should fail)
    const root4 = {
      owner: unsafeMissingOwner(),
      data: cred({ value: Field(18) }),
      threshold: Field(15),
      lowLimit: Field(10),
      highLimit: Field(20),
    };

    const assertResult4 = Node.eval(root4, spec.assert);
    assert.strictEqual(assertResult4.toBoolean(), false);
  });

  await t.test('Spec with ifThenElse as part of a complex assert', () => {
    const InputData = { value: Field };
    const spec = Spec(
      {
        data: Credential.Unsigned(InputData),
        threshold: Claim(Field),
        lowLimit: Constant(Field, Field(10)),
        highLimit: Constant(Field, Field(20)),
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
        outputClaim: Operation.property(data, 'value'),
      })
    );

    // 10 < value < threshold < highLimit (should pass)
    const root1 = {
      owner: unsafeMissingOwner(),
      data: cred({ value: Field(15) }),
      threshold: Field(18),
      lowLimit: Field(10),
      highLimit: Field(20),
    };

    const assertResult1 = Node.eval(root1, spec.assert);
    assert.strictEqual(assertResult1.toBoolean(), true);

    // 10 < threshold <= value = highLimit (should pass)
    const root2 = {
      owner: unsafeMissingOwner(),
      data: cred({ value: Field(20) }),
      threshold: Field(18),
      lowLimit: Field(10),
      highLimit: Field(20),
    };

    const assertResult2 = Node.eval(root2, spec.assert);
    assert.strictEqual(assertResult2.toBoolean(), true);

    // value <= lowLimit (should fail)
    const root3 = {
      owner: unsafeMissingOwner(),
      data: cred({ value: Field(10) }),
      threshold: Field(18),
      lowLimit: Field(10),
      highLimit: Field(20),
    };

    const assertResult3 = Node.eval(root3, spec.assert);
    assert.strictEqual(assertResult3.toBoolean(), false);

    // 10 < threshold <= value < highLimit (should fail)
    const root4 = {
      owner: unsafeMissingOwner(),
      data: cred({ value: Field(19) }),
      threshold: Field(18),
      lowLimit: Field(10),
      highLimit: Field(20),
    };

    const assertResult4 = Node.eval(root4, spec.assert);
    assert.strictEqual(assertResult4.toBoolean(), false);
  });

  await t.test('Spec with compute operations', async (t) => {
    await t.test('compute with addition', () => {
      const spec = Spec(
        {
          input: Credential.Unsigned({ x: Field, y: Field }),
        },
        ({ input }) => ({
          outputClaim: Operation.compute(
            [Operation.property(input, 'x'), Operation.property(input, 'y')],
            Field,
            (x, y) => x.add(y)
          ),
        })
      );

      const root: RootValue<typeof spec.inputs> = {
        owner: unsafeMissingOwner(),
        input: cred({ x: Field(10), y: Field(5) }),
      };

      const result = Node.eval(root, spec.outputClaim);
      assert.deepStrictEqual(result, Field(15));
    });

    await t.test('compute with boolean output', () => {
      const spec = Spec(
        {
          value: Credential.Unsigned(Field),
          threshold: Claim(Field),
        },
        ({ value, threshold }) => ({
          outputClaim: Operation.compute([value, threshold], Bool, (v, t) =>
            v.greaterThan(t)
          ),
        })
      );

      const validRoot: RootValue<typeof spec.inputs> = {
        owner: unsafeMissingOwner(),
        value: cred(Field(20)),
        threshold: Field(10),
      };

      const invalidRoot: RootValue<typeof spec.inputs> = {
        owner: unsafeMissingOwner(),
        value: cred(Field(5)),
        threshold: Field(10),
      };

      const validResult = Node.eval(validRoot, spec.outputClaim);
      const invalidResult = Node.eval(invalidRoot, spec.outputClaim);

      assert.strictEqual(validResult.toBoolean(), true);
      assert.strictEqual(invalidResult.toBoolean(), false);
    });

    await t.test('compute with nested operations', () => {
      const spec = Spec(
        {
          position: Credential.Unsigned({
            x: Field,
            y: Field,
          }),
          center: Claim({
            x: Field,
            y: Field,
          }),
          maxDistance: Claim(Field),
        },
        ({ position, center, maxDistance }) => {
          const distanceSquared = Operation.compute(
            [
              Operation.property(position, 'x'),
              Operation.property(position, 'y'),
              Operation.property(center, 'x'),
              Operation.property(center, 'y'),
            ],
            Field,
            (px, py, cx, cy) => {
              const dx = px.sub(cx);
              const dy = py.sub(cy);
              return dx.mul(dx).add(dy.mul(dy));
            }
          );

          return {
            assert: Operation.compute(
              [distanceSquared, maxDistance],
              Bool,
              (d, max) => d.lessThanOrEqual(max.mul(max))
            ),
            outputClaim: distanceSquared,
          };
        }
      );

      const root: RootValue<typeof spec.inputs> = {
        owner: unsafeMissingOwner(),
        position: cred({
          x: Field(3),
          y: Field(4),
        }),
        center: {
          x: Field(0),
          y: Field(0),
        },
        maxDistance: Field(5),
      };

      const assertResult = Node.eval(root, spec.assert);
      const dataResult = Node.eval(root, spec.outputClaim);

      assert.strictEqual(assertResult.toBoolean(), true);
      assert.deepStrictEqual(dataResult, Field(25));
    });
  });

  await t.test('Spec with nested properties', () => {
    const InputData = { age: Field, name: Bytes32 };
    const NestedInputData = { person: InputData, points: Field };

    const spec = Spec(
      {
        data: Credential.Unsigned(NestedInputData),
        targetAge: Claim(Field),
        targetPoints: Claim(Field),
      },
      ({ data, targetAge, targetPoints }) => ({
        assert: Operation.and(
          Operation.equals(
            Operation.property(Operation.property(data, 'person'), 'age'),
            targetAge
          ),
          Operation.equals(Operation.property(data, 'points'), targetPoints)
        ),
        outputClaim: Operation.property(
          Operation.property(data, 'person'),
          'name'
        ),
      })
    );

    const root: RootValue<typeof spec.inputs> = {
      owner: unsafeMissingOwner(),
      data: cred({
        person: { age: Field(25), name: Bytes32.fromString('Bob') },
        points: Field(100),
      }),
      targetAge: Field(25),
      targetPoints: Field(100),
    };

    const assertResult = Node.eval(root, spec.assert);
    const dataResult = Node.eval(root, spec.outputClaim);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Bytes32.fromString('Bob'));
  });

  await t.test('Spec with constant input', () => {
    const InputData = { age: Field, name: Bytes32 };
    const spec = Spec(
      {
        data: Credential.Unsigned(InputData),
        constAge: Constant(Field, Field(25)),
      },
      ({ data, constAge }) => ({
        assert: Operation.equals(Operation.property(data, 'age'), constAge),
        outputClaim: Operation.property(data, 'name'),
      })
    );

    const root: RootValue<typeof spec.inputs> = {
      owner: unsafeMissingOwner(),
      data: cred({ age: Field(25), name: Bytes32.fromString('Charlie') }),
      constAge: Field(25),
    };

    const assertResult = Node.eval(root, spec.assert);
    const dataResult = Node.eval(root, spec.outputClaim);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Bytes32.fromString('Charlie'));
  });

  await t.test('Spec with credential', () => {
    const InputData = { age: Field, name: Bytes32 };
    const spec = Spec(
      {
        signedData: Credential.Native(InputData),
        targetAge: Claim(Field),
        targetName: Claim(Bytes32),
      },
      ({ signedData, targetAge, targetName }) => ({
        assert: Operation.and(
          Operation.equals(Operation.property(signedData, 'age'), targetAge),
          Operation.equals(Operation.property(signedData, 'name'), targetName)
        ),
        outputClaim: Operation.property(signedData, 'age'),
      })
    );

    const data = { age: Field(30), name: Bytes32.fromString('David') };
    const signedData = Credential.sign(issuerKey, { owner, data });

    let userInputs: UserInputs<typeof spec.inputs> = {
      context: Field(0),
      ownerSignature: Signature.empty(),
      credentials: { signedData },
      claims: { targetAge: Field(30), targetName: Bytes32.fromString('David') },
    };

    let { privateInput, publicInput } = splitUserInputs(userInputs);

    let credentialOutputs: CredentialOutputs = {
      owner,
      credentials: [{ data, issuer: Field(1234), witness: undefined }],
    };
    let root = rootValue(spec, publicInput, privateInput, credentialOutputs);

    assert.deepStrictEqual(root, {
      owner,
      signedData: { data, issuer: Field(1234), witness: undefined },
      targetAge: Field(30),
      targetName: Bytes32.fromString('David'),
    });

    const assertResult = Node.eval(root, spec.assert);
    const dataResult = Node.eval(root, spec.outputClaim);

    assert.strictEqual(assertResult.toBoolean(), true);
    assert.deepStrictEqual(dataResult, Field(30));
  });
});
