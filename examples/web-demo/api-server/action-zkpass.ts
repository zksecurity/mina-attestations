import {
  assert,
  Operation,
  Presentation,
  PresentationRequest,
  Spec,
} from '../../../src/index.ts';
import { ORIGIN, SERVER_ID } from './config.ts';
import { queuePromise } from './async-queue.ts';
import { ZkPass } from '../../../src/imported.ts';

export { requestZkPassVerification, verifyZkPass };

const ACTION_ID = `${SERVER_ID}:zkpass-verification`;

await queuePromise(() => ZkPass.compileDependenciesPartial());
const zkPassCredential = await queuePromise(() => ZkPass.CredentialPartial());

const vk = await queuePromise(() => zkPassCredential.compile());

console.log('vk.hash:', vk.hash.toJSON());

const verificationSpec = Spec(
  {
    credential: zkPassCredential.spec,
  },
  ({ credential }) => {
    return {
      assert: [
        Operation.equals(
          Operation.verificationKeyHash(credential),
          Operation.constant(vk.hash)
        ),
      ],
      outputClaim: Operation.publicInput(credential),
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
    {},
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
  try {
    let presentation = Presentation.fromJSON(presentationJson);
    let nonce = presentation.serverNonce.toString();
    let request = openRequests.get(nonce);
    if (!request) throw Error('Unknown presentation');

    let output = await Presentation.verify(request, presentation, {
      verifierIdentity: ORIGIN,
    });

    // Check allocator address
    const allocatorAddress =
      '19a567b3b212a5b35bA0E3B600FbEd5c2eE9083d'.toLowerCase();
    // Validator address can change based on who's selected by the allocator
    // const validatorAddressExample = '0xb1C4C1E1Cdd5Cf69E27A3A08C8f51145c2E12C6a';

    assert(allocatorAddress === output.allocatorAddress.toHex());

    // check allocator signature
    ZkPass.verifyPublicInput(output);

    openRequests.delete(nonce);
  } catch (error: any) {
    console.error('Error verifying zkPass:', error);
    return { error: error instanceof Error ? error.message : 'Unknown error' };
  }
}
