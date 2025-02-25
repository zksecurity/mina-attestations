import {
  assert,
  Operation,
  Presentation,
  PresentationRequest,
  Spec,
  Claim,
  hashDynamic,
} from '../../../src/index.ts';
import { ORIGIN, SERVER_ID } from './config.ts';
import { queuePromise } from './async-queue.ts';
import { ZkPass } from '../../../src/imported.ts';
import { Field } from 'o1js';
import { Nullifier } from './nullifier-store.ts';

export { requestZkPassVerification, verifyZkPass };

const ACTION_ID = `${SERVER_ID}:zkpass-verification`;

// zkpass schema id, which specifies what web interaction the user had to perform
const schemaIdDev = '3ec11dea72464d729f76a7d42b7e98b8';
const schemaIdProd = '319ef6c9e03e47b38fb24420a1f2060c';
const isDev = ORIGIN === 'http://localhost:5173';
// const SCHEMA_ID = isDev ? schemaIdDev : schemaIdProd;
const SCHEMA_ID = schemaIdDev; // TODO: currently always assume dev schema because it matches the "example proof" and zkpass flow is not reliably working

// zkpass master public key that attests to their validators
// expected to be stable, did not rotate so far
const ALLOCATOR_ADDRESS = '19a567b3b212a5b35ba0e3b600fbed5c2ee9083d';

await queuePromise(() => ZkPass.compileDependenciesPartial());
const zkPassCredential = await queuePromise(() => ZkPass.CredentialPartial());

const vk = await queuePromise(() => zkPassCredential.compile());

console.log('vk.hash:', vk.hash.toJSON());

const verificationSpec = Spec(
  {
    credential: zkPassCredential.spec,

    // TODO we should have `Operation.action()` to get the `action` that was used for `context`
    actionId: Claim(Field),
  },
  ({ credential, actionId }) => {
    return {
      assert: Operation.equals(
        Operation.verificationKeyHash(credential),
        Operation.constant(vk.hash)
      ),
      outputClaim: Operation.record({
        zkpassInput: Operation.publicInput(credential),
        nullifier: Operation.hash(
          Operation.property(credential, 'nullifier'),
          actionId
        ),
      }),
    };
  }
);

let compiledRequestPromise = queuePromise(() =>
  Presentation.precompile(verificationSpec)
);

compiledRequestPromise.then(() =>
  console.log(`Compiled request after ${performance.now().toFixed(2)}ms`)
);

const openRequests = new Map<string, Request>();

async function createRequest() {
  let compiled = await compiledRequestPromise;

  let request = PresentationRequest.httpsFromCompiled(
    compiled,
    { actionId: hashDynamic(ACTION_ID) },
    { action: ACTION_ID }
  );
  openRequests.set(request.inputContext.serverNonce.toString(), request as any);
  return request;
}

type Request = Awaited<ReturnType<typeof createRequest>>;

async function requestZkPassVerification() {
  let request = await createRequest();
  return PresentationRequest.toJSON(request);
}

async function verifyZkPass(presentationJson: string) {
  let presentation = Presentation.fromJSON(presentationJson);
  let nonce = presentation.serverNonce.toString();
  let request = openRequests.get(nonce);
  if (!request) throw Error('Unknown presentation');

  let { zkpassInput, nullifier } = await Presentation.verify(
    request,
    presentation,
    { verifierIdentity: ORIGIN }
  );

  // assert that allocator signature is valid
  ZkPass.verifyPublicInput(zkpassInput);

  // check schema id
  assert(zkpassInput.schema.toHex() === SCHEMA_ID, 'invalid schema id');

  // check allocator address
  assert(
    zkpassInput.allocatorAddress.toHex() === ALLOCATOR_ADDRESS,
    'invalid allocator address'
  );

  // we could also require that the nullifier is only used once at this point
  // but that wouldn't make sense in the current example because there's no "action" associated to calling this endpoint
  // also, the use of nullifiers in this example is not safe because the nullifiers are pruned once in a while even though credentials never expire
  if (Nullifier.exists(nullifier)) {
    console.log('Nullifier already used:', nullifier);
  } else {
    console.log('New nullifier:', nullifier);
  }
  Nullifier.add(nullifier);

  openRequests.delete(nonce);
}
