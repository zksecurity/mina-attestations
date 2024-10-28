import { test } from 'node:test';
import assert from 'node:assert';
import { Field, Bytes } from 'o1js';
import { Claim, Constant, Operation, Spec } from '../src/program-spec.ts';
import {
  issuerKey,
  owner,
  ownerKey,
  randomPublicKey,
  zkAppAddress,
} from './test-utils.ts';
import { Credential } from '../src/credential-index.ts';
import { Presentation, PresentationRequest } from '../src/presentation.ts';

test('program with simple spec and signature credential', async (t) => {
  const Bytes32 = Bytes(32);

  const spec = Spec(
    {
      signedData: Credential.Simple({ age: Field, name: Bytes32 }),
      targetAge: Claim(Field),
      targetName: Constant(Bytes32, Bytes32.fromString('Alice')),
    },
    ({ signedData, targetAge, targetName }) => ({
      assert: Operation.and(
        Operation.equals(Operation.property(signedData, 'age'), targetAge),
        Operation.equals(Operation.property(signedData, 'name'), targetName)
      ),
      ouputClaim: Operation.property(signedData, 'age'),
    })
  );

  // presentation request
  let requestInitial = PresentationRequest.noContext(spec, {
    targetAge: Field(18),
  });
  let json = PresentationRequest.toJSON(requestInitial);

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

    let { proof } = presentation;
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
  const SignedData = Credential.Simple(InputData);

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
      ouputClaim: Operation.record({
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

    let { proof } = presentation;
    assert(proof, 'Proof should be generated');
    assert.deepStrictEqual(proof.publicOutput.owner, owner);
    const expectedIssuerField = SignedData.issuer(signedData.witness);
    assert.deepStrictEqual(proof.publicOutput.issuer, expectedIssuerField);
    assert.deepStrictEqual(proof.publicOutput.dummy, Field(123));
  });
});

test('presentation with context binding', async (t) => {
  const Bytes32 = Bytes(32);
  const InputData = { age: Field, name: Bytes32 };

  const spec = Spec(
    {
      signedData: Credential.Simple(InputData),
      targetAge: Claim(Field),
      targetName: Constant(Bytes32, Bytes32.fromString('Alice')),
    },
    ({ signedData, targetAge, targetName }) => ({
      assert: Operation.and(
        Operation.equals(Operation.property(signedData, 'age'), targetAge),
        Operation.equals(Operation.property(signedData, 'name'), targetName)
      ),
      ouputClaim: Operation.property(signedData, 'age'),
    })
  );
  const data = { age: Field(18), name: Bytes32.fromString('Alice') };
  const signedData = Credential.sign(issuerKey, { owner, data });

  await t.test('presentation with zk-app context', async (t) => {
    let request = PresentationRequest.zkApp(
      spec,
      { targetAge: Field(18) },
      { action: Field(123) }
    );

    let presentation = await Presentation.create(ownerKey, {
      request,
      context: { verifierIdentity: zkAppAddress },
      credentials: [signedData],
    });

    // verifies
    await Presentation.verify(request, presentation, {
      verifierIdentity: zkAppAddress,
    });

    // doesn't verify against different context
    await assert.rejects(
      () =>
        Presentation.verify(request, presentation, {
          verifierIdentity: randomPublicKey(),
        }),
      /Invalid context/,
      'Should throw an error for invalid context'
    );

    // doesn't verify against request for different action
    let request2 = PresentationRequest.zkApp(
      spec,
      { targetAge: Field(18) },
      { action: Field(124) }
    );
    await assert.rejects(
      () =>
        Presentation.verify(request2, presentation, {
          verifierIdentity: zkAppAddress,
        }),
      /Invalid context/,
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
