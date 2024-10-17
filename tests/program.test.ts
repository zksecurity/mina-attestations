import { test } from 'node:test';
import assert from 'node:assert';
import { Field, Bytes, PrivateKey } from 'o1js';
import { createProgram } from '../src/program.ts';
import { Input, Operation, Spec } from '../src/program-spec.ts';
import {
  createOwnerSignature,
  createSignatureCredential,
  owner,
} from './test-utils.ts';
import { Credential } from '../src/credentials.ts';

// TODO
let context = Field(0);

test('program with simple spec and signature credential', async (t) => {
  const Bytes32 = Bytes(32);
  const InputData = { age: Field, name: Bytes32 };
  const SignedData = Credential.signatureNative(InputData);

  const spec = Spec(
    {
      signedData: SignedData,
      targetAge: Input.claim(Field),
      targetName: Input.constant(Bytes32, Bytes32.fromString('Alice')),
    },
    ({ signedData, targetAge, targetName }) => ({
      assert: Operation.and(
        Operation.equals(Operation.property(signedData, 'age'), targetAge),
        Operation.equals(Operation.property(signedData, 'name'), targetName)
      ),
      data: Operation.property(signedData, 'age'),
    })
  );

  const program = createProgram(spec);

  await t.test('compile program', async () => {
    const vk = await program.compile();
    assert(vk, 'Verification key should be generated for zk program');
  });

  await t.test('run program with valid input', async () => {
    let data = { age: Field(18), name: Bytes32.fromString('Alice') };
    let signedData = createSignatureCredential(InputData, data);
    let ownerSignature = createOwnerSignature(context, [
      SignedData,
      signedData,
    ]);

    const proof = await program.run({
      context,
      ownerSignature,
      credentials: { signedData },
      claims: { targetAge: Field(18) },
    });

    assert(proof, 'Proof should be generated');

    assert.deepStrictEqual(
      proof.publicInput.claims.targetAge,
      Field(18),
      'Public input should match'
    );
    assert.deepStrictEqual(
      proof.publicOutput,
      Field(18),
      'Public output should match the age'
    );
  });

  await t.test('run program with invalid age input', async () => {
    const data = { age: Field(20), name: Bytes32.fromString('Alice') };
    const signedData = createSignatureCredential(InputData, data);
    let ownerSignature = createOwnerSignature(context, [
      SignedData,
      signedData,
    ]);

    await assert.rejects(
      async () =>
        await program.run({
          context,
          ownerSignature,
          credentials: { signedData },
          claims: { targetAge: Field(18) },
        }),
      (err) => {
        assert(err instanceof Error, 'Should throw an Error');
        assert(
          err.message.includes('Program assertion failed'),
          'Error message should include program assertion failure'
        );
        assert(
          err.message.includes('Constraint unsatisfied'),
          'Error message should include unsatisfied constraint'
        );
        return true;
      },
      'Program should fail with invalid input'
    );
  });

  await t.test('run program with invalid name input', async () => {
    const data = { age: Field(18), name: Bytes32.fromString('Bob') };
    const signedData = createSignatureCredential(InputData, data);
    let ownerSignature = createOwnerSignature(context, [
      SignedData,
      signedData,
    ]);

    await assert.rejects(
      async () =>
        await program.run({
          context,
          ownerSignature,
          credentials: { signedData },
          claims: { targetAge: Field(18) },
        }),
      (err) => {
        assert(err instanceof Error, 'Should throw an Error');
        assert(
          err.message.includes('Program assertion failed'),
          'Error message should include program assertion failure'
        );
        assert(
          err.message.includes('Constraint unsatisfied'),
          'Error message should include unsatisfied constraint'
        );
        return true;
      },
      'Program should fail with invalid input'
    );
  });
});

test('program with owner and issuer operations', async (t) => {
  const InputData = { dummy: Field };
  const SignedData = Credential.signatureNative(InputData);

  const spec = Spec(
    {
      signedData: SignedData,
      expectedDummy: Input.constant(Field, Field(123)),
    },
    ({ signedData, expectedDummy }) => ({
      assert: Operation.equals(
        Operation.property(signedData, 'dummy'),
        expectedDummy
      ),
      data: Operation.record({
        owner: Operation.owner(),
        issuer: Operation.issuer('signedData'),
        dummy: Operation.property(signedData, 'dummy'),
      }),
    })
  );

  const program = createProgram(spec);

  await t.test('compile program', async () => {
    const vk = await program.compile();
    assert(vk, 'Verification key should be generated for zk program');
  });

  await t.test('run program with valid input', async () => {
    const dummyData = { dummy: Field(123) };
    const signedData = createSignatureCredential(InputData, dummyData);
    let ownerSignature = createOwnerSignature(context, [
      SignedData,
      signedData,
    ]);

    const proof = await program.run({
      context,
      ownerSignature,
      credentials: { signedData },
      claims: {},
    });

    assert(proof, 'Proof should be generated');

    assert.deepStrictEqual(proof.publicOutput.owner, owner);

    const expectedIssuerField = SignedData.issuer(signedData.private);
    assert.deepStrictEqual(proof.publicOutput.issuer, expectedIssuerField);

    assert.deepStrictEqual(proof.publicOutput.dummy, Field(123));
  });
});
