import { Bool, Bytes, Field, UInt64 } from 'o1js';
import {
  Claim,
  Constant,
  Credential,
  DynamicRecord,
  DynamicString,
  Operation,
  Presentation,
  PresentationRequest,
  Spec,
  assert,
  hashDynamic,
} from '../../../src/index.ts';
import { getPublicKey } from './keys.ts';
import { ORIGIN, SERVER_ID } from './config.ts';
import { Nullifier } from './nullifier-store.ts';
import { z } from 'zod';
import { createJsonStore } from './json-store.ts';
import { queuePromise } from './async-queue.ts';

export { requestVote, verifyVote, getVotes };

const ACTION_ID = `${SERVER_ID}:poll:0`;

const String = DynamicString({ maxLength: 50 });

// use a `DynamicRecord` to allow more fields in the credential than we explicitly list
const Schema = DynamicRecord(
  {
    nationality: String,
    birthDate: UInt64,
    expiresAt: UInt64,
    id: Bytes(16),
  },
  { maxEntries: 20 }
);

const votingSpec = Spec(
  {
    credential: Credential.Native(Schema),
    expectedIssuer: Claim(Field),
    createdAt: Claim(UInt64),
    inFavor: Claim(Bool),

    // TODO we should have `Operation.action()` to get the `action` that was used for `context`
    actionId: Claim(Field),

    unitedStates: Constant(String, String.from('United States of America')),
    eighteenYears: Constant(
      UInt64,
      UInt64.from(18 * 365 * 24 * 60 * 60 * 1000)
    ),
  },
  ({
    credential,
    expectedIssuer,
    createdAt,
    actionId,
    unitedStates,
    eighteenYears,
  }) => {
    // extract properties from the credential
    let issuer = Operation.issuer(credential);
    let expiresAt = Operation.property(credential, 'expiresAt');
    let nationality = Operation.property(credential, 'nationality');
    let birthDate = Operation.property(credential, 'birthDate');

    return {
      assert: [
        // - the credential issuer matches the expected (public) input, i.e. this server
        Operation.equals(issuer, expectedIssuer),

        // - the credential is not expired (by comparing with the current date)
        Operation.lessThanEq(createdAt, expiresAt),

        // - the nationality is not USA
        Operation.not(Operation.equals(nationality, unitedStates)),

        // - the user is older than 18 years (by comparing with the current date)
        Operation.lessThan(Operation.add(birthDate, eighteenYears), createdAt),
      ],

      // return a nullifier
      // this won't reveal the data because our Schema with the `id` field has enough entropy
      outputClaim: Operation.record({
        nullifier: Operation.hash(credential, actionId),
      }),
    };
  }
);

// set off compiling of the request -- this promise is needed when verifying
let compiledRequestPromise = queuePromise(() =>
  Presentation.precompile(votingSpec)
);
compiledRequestPromise.then(() =>
  console.log(`Compiled request after ${performance.now().toFixed(2)}ms`)
);

const openRequests = new Map<string, Request>();

async function createRequest(inFavor: boolean, createdAt: number) {
  let expectedIssuer = Credential.Native.issuer(getPublicKey());
  let compiled = await compiledRequestPromise;

  let request = PresentationRequest.httpsFromCompiled(
    compiled,
    {
      expectedIssuer,
      createdAt: UInt64.from(createdAt),
      inFavor: Bool(inFavor),
      actionId: hashDynamic(ACTION_ID),
    },
    { action: ACTION_ID }
  );
  openRequests.set(request.inputContext.serverNonce.toString(), request as any);
  return request;
}

type Request = Awaited<ReturnType<typeof createRequest>>;

let Vote = z.union([z.literal('btc'), z.literal('eth')]);

async function requestVote(voteStr: unknown) {
  let vote = Vote.parse(voteStr);
  let request = await createRequest(vote === 'btc', Date.now());
  return PresentationRequest.toJSON(request);
}

const voteStore = createJsonStore('votes.json', { btc: 0, eth: 0 });

async function verifyVote(presentationJson: string) {
  try {
    let presentation = Presentation.fromJSON(presentationJson);
    let nonce = presentation.serverNonce.toString();
    let request = openRequests.get(nonce);
    if (!request) throw Error('Unknown presentation');

    // date must be within 5 minutes of the current date
    let createdAt = Number(request.claims.createdAt);
    assert(createdAt > Date.now() - 5 * 60 * 1000, 'Expired presentation');

    // verify the presentation
    let { nullifier } = await Presentation.verify(request, presentation, {
      verifierIdentity: ORIGIN,
    });
    openRequests.delete(nonce);

    // check that the nullifier hasn't been used before; if not, store it
    if (Nullifier.exists(nullifier)) {
      throw Error('Duplicate nullifier: Only allowed to vote once');
    }
    Nullifier.add(nullifier);

    // add the vote!
    let vote: 'btc' | 'eth' = request.claims.inFavor.toBoolean()
      ? 'btc'
      : 'eth';
    voteStore.update((votes) => {
      votes[vote]++;
    });
    return { voteCounted: true, failureReason: '' };
  } catch (error: any) {
    console.error('Failed to verify vote:', error);
    return { voteCounted: false, failureReason: error.message as string };
  }
}

function getVotes() {
  return voteStore.get();
}
