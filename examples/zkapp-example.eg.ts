/**
 * Example where the verifier is a zkApp.
 */
import {
  SmartContract,
  Bytes,
  Int64,
  UInt64,
  declareMethods,
  Mina,
  TokenId,
} from 'o1js';
import {
  Operation,
  Claim,
  Credential,
  Presentation,
  PresentationRequest,
  DynamicString,
  DynamicRecord,
  Schema,
  PresentationSpec,
} from 'mina-attestations';
import {
  issuer,
  issuerKey,
  owner,
  ownerKey,
  zkAppAddress,
} from '../tests/test-utils.ts';

// example schema of the credential
const Bytes16 = Bytes(16);

const schema = Schema({
  nationality: Schema.String,
  name: Schema.String,
  birthDate: Int64,
  id: Bytes16,
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
// ZKAPP VERIFIER: define a presentation and SmartContract

const String = DynamicString({ maxLength: 100 });

const Subschema = DynamicRecord(
  {
    nationality: String,
    expiresAt: UInt64,
  },
  { maxEntries: 20 }
);

let spec = PresentationSpec(
  {
    credential: Credential.Native(Subschema),
    createdAt: Claim(UInt64),
  },
  ({ credential, createdAt }) => ({
    assert: [
      // 1. not from the United States
      Operation.not(
        Operation.equals(
          Operation.property(credential, 'nationality'),
          Operation.constant(String.from('United States'))
        )
      ),

      // 2. credential is not expired
      Operation.lessThanEq(
        createdAt,
        Operation.property(credential, 'expiresAt')
      ),
    ],
    // we expose the credential's issuer, for the verifier to check
    outputClaim: Operation.issuer(credential),
  })
);

let precompiled = await Presentation.precompile(spec);

// this class defines the zkApp input type
// using this class in a zkApp will hard-code the particular presentation spec that it verifies
class ProvablePresentation extends precompiled.ProvablePresentation {}

let info = (await precompiled.program.program.analyzeMethods()).run;
console.log('presentation circuit summary', info?.summary());

console.log('✅ VERIFIER: compiled presentation spec');

class ZkAppVerifier extends SmartContract {
  async verifyPresentation(presentation: ProvablePresentation) {
    // verify the presentation, and receive its claims for further validation and usage
    let { claims, outputClaim } = presentation.verify({
      publicKey: this.address,
      tokenId: this.tokenId,
      methodName: 'verifyPresentation',
    });

    // check that `createdAt` is a recent timestamp, by adding a precondition on the current slot.
    // we have to convert timestamp (in ms) to 3-minute slots since genesis
    let { createdAt } = claims;
    const genesisTimestamp = +new Date('2024-06-04T16:00:00.000000-08:00');
    const slot = 3 * 60 * 1000;
    let slotEstimate = createdAt.sub(genesisTimestamp).div(slot).toUInt32();
    // allow `createdAt` to be about 5 slots old
    this.currentSlot.requireBetween(slotEstimate, slotEstimate.add(5));

    // check that the issuer matches a hard-coded public key
    outputClaim.assertEquals(
      Credential.Native.issuer(issuer),
      'invalid issuer'
    );
  }
}
declareMethods(ZkAppVerifier, {
  verifyPresentation: [ProvablePresentation as any], // TODO bad TS interface
});

await ZkAppVerifier.compile();
let cs = await ZkAppVerifier.analyzeMethods();
console.log('zkApp rows', cs.verifyPresentation?.rows);
console.log('✅ VERIFIER: compiled zkapp that verifies the presentation');

// ZKAPP VERIFIER, outside circuit: request a presentation

let request = PresentationRequest.zkAppFromCompiled(
  precompiled,
  { createdAt: UInt64.from(Date.now()) },
  {
    // this added context ensures that the presentation can't be used outside the target zkApp
    publicKey: zkAppAddress,
    tokenId: TokenId.default,
    methodName: 'verifyPresentation',
  }
);
let requestJson = PresentationRequest.toJSON(request);

console.log(
  '✅ VERIFIER: created presentation request:',
  requestJson.slice(0, 500) + '...'
);

// ---------------------------------------------
// WALLET: deserialize request and create presentation

let deserialized = PresentationRequest.fromJSON('zk-app', requestJson);

console.time('create');
let presentation = await Presentation.create(ownerKey, {
  request: deserialized,
  credentials: [storedCredential],
  context: undefined,
});
console.timeEnd('create');

let serialized = Presentation.toJSON(presentation);
console.log(
  '✅ WALLET: created presentation:',
  serialized.slice(0, 2000) + '...'
);

// ---------------------------------------------
// ZKAPP VERIFIER: call zkapp with presentation and create transaction

let presentation2 = Presentation.fromJSON(serialized);
let Local = await Mina.LocalBlockchain();
Mina.setActiveInstance(Local);

let tx = await Mina.transaction(() =>
  new ZkAppVerifier(zkAppAddress).verifyPresentation(
    ProvablePresentation.from(presentation2)
  )
);
await tx.prove();

console.log('✅ VERIFIER: verified presentation', tx.toPretty());
