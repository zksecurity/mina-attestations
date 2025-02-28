import { test } from 'node:test';
import assert from 'node:assert';
import { Credential } from '../src/credential-index.ts';
import {
  StoredCredentialSchema,
  PresentationRequestSchema,
} from '../src/validation.ts';
import { Bytes, Field, PublicKey, Signature } from 'o1js';
import { owner, issuerKey, zkAppIdentity } from './test-utils.ts';
import { Spec, Claim } from '../src/program-spec.ts';
import { createProgram } from '../src/program.ts';
import { createUnsigned } from '../src/credential.ts';
import { Operation, PresentationRequest } from '../src/index.ts';

const Bytes32 = Bytes(32);

test('StoredCredentialSchema validation', async (t) => {
  await t.test('validates native credential', () => {
    const data = { age: Field(25) };
    const signedCredential = Credential.sign(issuerKey, { owner, data });
    const serialized = Credential.toJSON(signedCredential);
    const parsed = JSON.parse(serialized);

    const result = StoredCredentialSchema.safeParse(parsed);
    assert(
      result.success,
      'Native credential JSON should be valid: ' +
        (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
    );
  });

  await t.test('validates imported credential', async () => {
    const InputData = { age: Field, name: Bytes32 };
    const inputProofSpec = Spec(
      { inputOwner: Claim(PublicKey), data: Claim(InputData) },
      ({ inputOwner, data }) => ({
        outputClaim: Operation.record({ owner: inputOwner, data }),
      })
    );

    // create imported credential
    const Imported = await Credential.Imported.fromProgram(
      createProgram(inputProofSpec).program
    );
    let data = { age: Field(18), name: Bytes32.fromString('Alice') };
    let provedData = await Imported.create(
      { context: Field(0), claims: { inputOwner: owner, data } },
      {
        credentials: {},
        ownerSignature: Signature.empty(), // no credential => no signature verification
      }
    );

    const serialized = Credential.toJSON(provedData);
    const parsed = JSON.parse(serialized);

    const result = StoredCredentialSchema.safeParse(parsed);
    assert(
      result.success,
      'Imported credential JSON should be valid: ' +
        (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
    );
  });

  await t.test('should validate a valid unsigned credential', () => {
    const unsignedCredential = createUnsigned({
      age: Field(42),
      name: Bytes32.fromString('Alice'),
    });

    const serialized = Credential.toJSON(unsignedCredential);
    const parsed = JSON.parse(serialized);

    const result = StoredCredentialSchema.safeParse(parsed);
    assert(
      result.success,
      'Unsigned credential JSON should be valid: ' +
        (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
    );
  });
});

test('PresentationRequestSchema validation', async (t) => {
  await t.test('validates complex presentation request', () => {
    const InputData = { age: Field, name: Bytes32 };
    const NestedInputData = { person: InputData, points: Field };

    const spec = Spec(
      {
        data: Credential.Native(NestedInputData),
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

    const request = PresentationRequest.zkApp(
      spec,
      { targetAge: Field(25), targetPoints: Field(100) },
      { ...zkAppIdentity, methodName: 'myMethod' }
    );

    const serialized = JSON.parse(PresentationRequest.toJSON(request));

    const result = PresentationRequestSchema.safeParse(serialized);
    assert(
      result.success,
      'ZkApp presentation request should be valid: ' +
        (result.success ? '' : JSON.stringify(result.error.issues, null, 2))
    );
  });
});
