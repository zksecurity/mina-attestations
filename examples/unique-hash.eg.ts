import { Bytes, Field, Int64, UInt64 } from 'o1js';
import {
  Spec,
  Operation,
  Claim,
  Credential,
  Presentation,
  PresentationRequest,
  assert,
  DynamicString,
  DynamicArray,
  DynamicRecord,
  Schema,
  hashDynamic,
} from 'mina-attestations';
import {
  issuer,
  issuerKey,
  owner,
  ownerKey,
  randomPublicKey,
} from '../tests/test-utils.ts';

// example schema of the credential, which has enough entropy to be hashed into a unique id
const Bytes16 = Bytes(16);

const schema = Schema({
  /**
   * Nationality of the owner.
   */
  nationality: Schema.String,

  /**
   * Full name of the owner.
   */
  name: Schema.String,

  /**
   * Date of birth of the owner.
   */
  birthDate: Int64,

  /**
   * Owner ID (16 bytes).
   */
  id: Bytes16,

  /**
   * Timestamp when the credential expires.
   */
  expiresAt: Schema.Number,
});

// ---------------------------------------------
// ISSUER: issue a signed credential to the owner

let data = schema.from({
  nationality: 'United States of America',
  name: 'John Doe',
  birthDate: Int64.from(Date.UTC(1940, 1, 1)),
  id: Bytes16.random(),
  expiresAt: Date.UTC(2028, 7, 1),
});
let credential = Credential.sign(issuerKey, { owner, data });
let credentialJson = Credential.toJSON(credential);

console.log('✅ ISSUER: issued credential:', credentialJson);

// ---------------------------------------------
// WALLET: deserialize, validate and store the credential

let storedCredential = await Credential.fromJSON(credentialJson);

await Credential.validate(storedCredential);

console.log('✅ WALLET: imported and validated credential');

// ---------------------------------------------
// VERIFIER: request a presentation

// it's enough to know a subset of the schema to create the request
const String = DynamicString({ maxLength: 50 });

const Subschema = DynamicRecord(
  {
    nationality: String,
    expiresAt: UInt64, // we don't have to match the original order of keys
    id: Bytes16,
  },
  // have to specify maximum number of entries of the original schema
  { maxEntries: 20 }
);

const FieldArray = DynamicArray(Field, { maxLength: 100 });

const spec = Spec(
  {
    credential: Credential.Native(Subschema),
    acceptedNations: Claim(FieldArray), // we represent nations as their hashes for efficiency
    acceptedIssuers: Claim(FieldArray),
    currentDate: Claim(UInt64),
    appId: Claim(String),
  },
  ({ credential, acceptedNations, acceptedIssuers, currentDate, appId }) => {
    // extract properties from the credential
    let nationality = Operation.property(credential, 'nationality');
    let issuer = Operation.issuer(credential);
    let expiresAt = Operation.property(credential, 'expiresAt');

    // we assert that:
    // 1. the owner has one of the accepted nationalities
    // 2. the credential was issued by one of the accepted issuers
    // 3. the credential is not expired (by comparing with the current date)
    let assert = Operation.and(
      Operation.equalsOneOf(Operation.hash(nationality), acceptedNations),
      Operation.equalsOneOf(issuer, acceptedIssuers),
      Operation.lessThanEq(currentDate, expiresAt)
    );

    // we expose a unique hash of the credential data, to be used as nullifier
    // note: since the credential contains a 16 byte = 128 bit random ID, it has enough
    // entropy such that exposing this hash will not reveal the credential data
    let outputClaim = Operation.record({
      nullifier: Operation.hash(credential, appId),
    });

    return { assert, outputClaim };
  }
);

const acceptedNations = ['United States of America', 'Canada', 'Mexico'];
const acceptedIssuers = [issuer, randomPublicKey(), randomPublicKey()].map(
  (pk) => Credential.Native.issuer(pk)
);

let request = PresentationRequest.https(
  spec,
  {
    acceptedNations: FieldArray.from(
      acceptedNations.map((s) => hashDynamic(s))
    ),
    acceptedIssuers: FieldArray.from(acceptedIssuers),
    currentDate: UInt64.from(Date.now()),
    appId: String.from('my-app-id:123'),
  },
  { action: 'my-app-id:123:authenticate' }
);
let requestJson = PresentationRequest.toJSON(request);

console.log(
  '✅ VERIFIER: created presentation request:',
  requestJson.slice(0, 500) + '...'
);

// ---------------------------------------------
// WALLET: deserialize request and create presentation

console.time('compile');
let deserialized = PresentationRequest.fromJSON('https', requestJson);
let compiled = await Presentation.compile(deserialized);
console.timeEnd('compile');

let info = (await compiled.program.program.analyzeMethods()).run;
console.log('circuit gates summary', info?.summary());

console.time('create');
let presentation = await Presentation.create(ownerKey, {
  request: compiled,
  credentials: [storedCredential],
  context: { verifierIdentity: 'my-app.xyz' },
});
console.timeEnd('create');

let serialized = Presentation.toJSON(presentation);
console.log(
  '✅ WALLET: created presentation:',
  serialized.slice(0, 2000) + '...'
);

// ---------------------------------------------
// VERIFIER: verify the presentation against the request we submitted, and check that the nullifier was not used yet

let presentation2 = Presentation.fromJSON(serialized);

let outputClaim = await Presentation.verify(request, presentation2, {
  verifierIdentity: 'my-app.xyz',
});
console.log('✅ VERIFIER: verified presentation');

let existingNullifiers = new Set([0x13c43f30n, 0x370f3473n, 0xe1fe0cdan]);

let { nullifier } = outputClaim;
assert(
  !existingNullifiers.has(nullifier.toBigInt()),
  'Nullifier should be unique'
);
console.log('✅ VERIFIER: checked nullifier uniqueness');
