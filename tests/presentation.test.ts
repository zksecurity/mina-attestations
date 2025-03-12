import { test } from 'node:test';
import assert from 'node:assert';
import { Field, Bytes } from 'o1js';
import { Claim, Constant, Spec } from '../src/program-spec.ts';
import {
  issuerKey,
  owner,
  ownerKey,
  randomPublicKey,
  zkAppIdentity,
} from './test-utils.ts';
import { Credential } from '../src/credential-index.ts';
import { Presentation, PresentationRequest } from '../src/presentation.ts';
import { Operation } from '../src/operation.ts';
import { PresentationRequestSchema } from '../src/validation.ts';

const zkappContext = { ...zkAppIdentity, methodName: 'myMethod' };

test('program with simple spec and native credential', async (t) => {
  const Bytes32 = Bytes(32);

  const spec = Spec(
    {
      signedData: Credential.Native({ age: Field, name: Bytes32 }),
      targetAge: Claim(Field),
      targetName: Constant(Bytes32, Bytes32.fromString('Alice')),
    },
    ({ signedData, targetAge, targetName }) => ({
      assert: Operation.and(
        Operation.equals(Operation.property(signedData, 'age'), targetAge),
        Operation.equals(Operation.property(signedData, 'name'), targetName)
      ),
      outputClaim: Operation.property(signedData, 'age'),
    })
  );

  // presentation request
  let requestInitial = PresentationRequest.noContext(spec, {
    targetAge: Field(18),
  });
  let json = PresentationRequest.toJSON(requestInitial);

  let serialized = JSON.parse(json);

  const result = PresentationRequestSchema.safeParse(serialized);
  assert(
    result.success,
    'No-context presentation request should be valid: ' +
      (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
  );

  // wallet: deserialize and compile request
  let deserialized = PresentationRequest.fromJSON('no-context', json);
  let request = await Presentation.compile(deserialized);

  await t.test('compile program', async () => {
    assert(
      await request.program.compile(),
      'Verification key should be generated for zk program'
    );
  });

  await t.test('run program with valid input', async () => {
    // issuance
    let data = { age: Field(18), name: Bytes32.fromString('Alice') };
    let signedData = Credential.sign(issuerKey, { owner, data });

    // presentation
    let presentation = await Presentation.create(ownerKey, {
      request,
      credentials: [signedData],
      context: undefined,
    });

    // verifies
    await Presentation.verify(request, presentation, undefined);

    let { claims, outputClaim, proof } = presentation;
    assert(proof, 'Proof should be generated');
    assert.deepStrictEqual(
      claims.targetAge,
      Field(18),
      'Public input should match'
    );
    assert.deepStrictEqual(
      outputClaim,
      Field(18),
      'Public output should match the age'
    );
  });

  await t.test('run program with invalid age input', async () => {
    const data = { age: Field(20), name: Bytes32.fromString('Alice') };
    let signedData = Credential.sign(issuerKey, { owner, data });

    await assert.rejects(
      async () =>
        await Presentation.create(ownerKey, {
          request,
          credentials: [signedData],
          context: undefined,
        }),
      /Program assertion failed/,
      'Program should fail with invalid input'
    );
  });

  await t.test('run program with invalid name input', async () => {
    const data = { age: Field(18), name: Bytes32.fromString('Bob') };
    let signedData = Credential.sign(issuerKey, { owner, data });

    await assert.rejects(
      () =>
        Presentation.create(ownerKey, {
          request,
          credentials: [signedData],
          context: undefined,
        }),
      /Program assertion failed/,
      'Program should fail with invalid input'
    );
  });
});

test('program with owner and issuer operations', async (t) => {
  const InputData = { dummy: Field };
  const SignedData = Credential.Native(InputData);

  const spec = Spec(
    {
      signedData: SignedData,
      expectedDummy: Constant(Field, Field(123)),
    },
    ({ signedData, expectedDummy }) => ({
      assert: Operation.equals(
        Operation.property(signedData, 'dummy'),
        expectedDummy
      ),
      outputClaim: Operation.record({
        owner: Operation.owner,
        issuer: Operation.issuer(signedData),
        dummy: Operation.property(signedData, 'dummy'),
      }),
    })
  );
  let requestInitial = PresentationRequest.noContext(spec, {});
  let request = await Presentation.compile(requestInitial);

  await t.test('compile program', async () => {
    assert(await request.program.compile(), 'Program should compile');
  });

  await t.test('run program with valid input', async () => {
    let dummyData = { dummy: Field(123) };
    let signedData = Credential.sign(issuerKey, { owner, data: dummyData });
    let presentation = await Presentation.create(ownerKey, {
      request,
      credentials: [signedData],
      context: undefined,
    });
    await Presentation.verify(request, presentation, undefined);

    let { outputClaim, proof } = presentation;
    assert(proof, 'Proof should be generated');

    assert.deepStrictEqual(outputClaim.owner, owner);
    const expectedIssuerField = SignedData.issuer(signedData.witness);
    assert.deepStrictEqual(outputClaim.issuer, expectedIssuerField);
    assert.deepStrictEqual(outputClaim.dummy, Field(123));
  });
});

test('presentation with context binding', async (t) => {
  const Bytes32 = Bytes(32);
  const InputData = { age: Field, name: Bytes32 };

  const spec = Spec(
    {
      signedData: Credential.Native(InputData),
      targetAge: Claim(Field),
      targetName: Constant(Bytes32, Bytes32.fromString('Alice')),
    },
    ({ signedData, targetAge, targetName }) => ({
      assert: Operation.and(
        Operation.equals(Operation.property(signedData, 'age'), targetAge),
        Operation.equals(Operation.property(signedData, 'name'), targetName)
      ),
      outputClaim: Operation.property(signedData, 'age'),
    })
  );
  const data = { age: Field(18), name: Bytes32.fromString('Alice') };
  const signedData = Credential.sign(issuerKey, { owner, data });

  await t.test('presentation with zk-app context', async (t) => {
    let request = PresentationRequest.zkApp(
      spec,
      { targetAge: Field(18) },
      zkappContext
    );

    let presentation = await Presentation.create(ownerKey, {
      request,
      context: undefined,
      credentials: [signedData],
    });

    // verifies
    await Presentation.verify(request, presentation, undefined);

    // doesn't verify against different context
    await assert.rejects(
      () =>
        Presentation.verify(
          {
            ...request,
            inputContext: {
              ...request.inputContext,
              verifierIdentity: {
                ...zkAppIdentity,
                network: 'mainnet',
              },
            },
          },
          presentation,
          undefined
        ),
      /Invalid proof/,
      'Should throw an error for invalid context'
    );

    // doesn't verify against request for different action
    let request2 = PresentationRequest.zkApp(
      spec,
      { targetAge: Field(18) },
      { ...zkappContext, methodName: 'otherMethod' }
    );
    await assert.rejects(
      () => Presentation.verify(request2, presentation, undefined),
      /Invalid proof/,
      'Should throw an error for invalid context'
    );
  });

  await t.test('presentation with https context', async () => {
    let request = PresentationRequest.https(
      spec,
      { targetAge: Field(18) },
      { action: 'POST /api/verify' }
    );

    let presentation = await Presentation.create(ownerKey, {
      request,
      credentials: [signedData],
      context: { verifierIdentity: 'test.com' },
    });

    await Presentation.verify(request, presentation, {
      verifierIdentity: 'test.com',
    });
  });
});

test('serialize presentation', async (t) => {
  const Bytes32 = Bytes(32);
  const InputData = { age: Field, name: Bytes32 };

  const spec = Spec(
    {
      signedData: Credential.Native(InputData),
      targetAge: Claim(Field),
      targetName: Constant(Bytes32, Bytes32.fromString('Alice')),
    },
    ({ signedData, targetAge, targetName }) => ({
      assert: Operation.and(
        Operation.equals(Operation.property(signedData, 'age'), targetAge),
        Operation.equals(Operation.property(signedData, 'name'), targetName)
      ),
      outputClaim: Operation.property(signedData, 'age'),
    })
  );
  const data = { age: Field(18), name: Bytes32.fromString('Alice') };
  const signedData = Credential.sign(issuerKey, { owner, data });

  await t.test('serialize presentation with zk-app context', async (t) => {
    let request = PresentationRequest.zkApp(
      spec,
      { targetAge: Field(18) },
      zkappContext
    );

    let presentation = await Presentation.create(ownerKey, {
      request,
      context: undefined,
      credentials: [signedData],
    });

    assert(presentation.proof, 'Proof should be generated');

    let serialized = Presentation.toJSON(presentation);
    let deserialized = Presentation.fromJSON(serialized);
    let reserialized = Presentation.toJSON(deserialized);

    assert.deepStrictEqual(deserialized, presentation);
    assert.deepStrictEqual(reserialized, serialized);
  });
});
