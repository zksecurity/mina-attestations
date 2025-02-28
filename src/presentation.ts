import {
  Field,
  type JsonProof,
  Poseidon,
  PrivateKey,
  Provable,
  PublicKey,
  Signature,
  Struct,
  TokenId,
  UInt32,
  VerificationKey,
  verify,
} from 'o1js';
import {
  Spec,
  type Input,
  type Claims,
  isCredentialSpec,
} from './program-spec.ts';
import { createProgram, type Program } from './program.ts';
import {
  credentialMatchesSpec,
  hashCredential,
  type CredentialSpec,
  type StoredCredential,
} from './credential.ts';
import { assert, zip } from './util.ts';
import {
  hashContext,
  computeHttpsContext,
  computeZkAppContext,
  type NetworkId,
  type WalletDerivedContext,
  type HttpsInputContext,
  type HttpsWalletContext,
  type ZkAppInputContext,
} from './context.ts';
import { NestedProvable } from './nested.ts';
import {
  serializeSpec,
  serializeInputContext,
  deserializeSpec,
  deserializeInputContext,
} from './serialize-spec.ts';
import {
  deserializeNestedProvableValue,
  deserializeProvable,
  serializeNestedProvableValue,
  serializeProvable,
} from './serialize-provable.ts';
import { PresentationRequestSchema } from './validation.ts';

// external API
export { PresentationRequest, HttpsRequest, ZkAppRequest, Presentation };

// internal
export { type PresentationRequestType, hashClaims, pickCredentials };

type PresentationRequestType = 'no-context' | 'zk-app' | 'https';

type PresentationRequest<
  RequestType extends PresentationRequestType = PresentationRequestType,
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>,
  InputContext = any,
  WalletContext = any
> = {
  type: RequestType;
  spec: Spec<Output, Inputs>;
  claims: Claims<Inputs>;
  inputContext: InputContext;
  program?: unknown;
  verificationKey?: VerificationKey;

  deriveContext(
    /**
     * Context that is passed in from the input request / server-side
     */
    inputContext: InputContext,
    /**
     * Application-specific context that is passed in from the wallet / client-side
     */
    walletContext: WalletContext,
    /**
     * Context automatically (re-)derived on the client
     */
    derivedContext: WalletDerivedContext
  ): Field;
};

type CompiledRequest<Output, Inputs extends Record<string, Input>> = {
  spec: Spec<Output, Inputs>;
  program: Program<Output, Inputs>;
  verificationKey: VerificationKey;
};

const PresentationRequest = {
  https<Output, Inputs extends Record<string, Input>>(
    spec: Spec<Output, Inputs>,
    claims: Claims<Inputs>,
    context: { action: string }
  ) {
    // generate random nonce on "the server"
    let serverNonce = Field.random();

    return HttpsRequest({
      spec,
      claims,
      program: createProgram(spec),
      inputContext: { type: 'https', action: context.action, serverNonce },
    });
  },

  httpsFromCompiled<Output, Inputs extends Record<string, Input>>(
    compiled: CompiledRequest<Output, Inputs>,
    claims: Claims<Inputs>,
    context: { action: string }
  ) {
    let serverNonce = Field.random();

    return HttpsRequest({
      spec: compiled.spec,
      claims,
      program: compiled.program,
      verificationKey: compiled.verificationKey,
      inputContext: { type: 'https', action: context.action, serverNonce },
    });
  },

  zkApp<Output, Inputs extends Record<string, Input>>(
    spec: Spec<Output, Inputs>,
    claims: Claims<Inputs>,
    context: {
      publicKey: PublicKey;
      tokenId?: Field;
      methodName: string;
      network: NetworkId;
      nonce?: UInt32;
    }
  ) {
    return ZkAppRequest({
      spec,
      claims,
      program: createProgram(spec),
      inputContext: {
        type: 'zk-app',
        verifierIdentity: {
          publicKey: context.publicKey,
          tokenId: context.tokenId ?? TokenId.default,
          network: context.network,
        },
        action: context.methodName,
        serverNonce: context.nonce?.value ?? Field(0),
      },
    });
  },

  zkAppFromCompiled<Output, Inputs extends Record<string, Input>>(
    compiled: CompiledRequest<Output, Inputs>,
    claims: Claims<Inputs>,
    context: {
      publicKey: PublicKey;
      tokenId?: Field;
      methodName: string;
      network: NetworkId;
      nonce?: UInt32;
    }
  ) {
    return ZkAppRequest({
      spec: compiled.spec,
      claims,
      program: compiled.program,
      verificationKey: compiled.verificationKey,
      inputContext: {
        type: 'zk-app',
        verifierIdentity: {
          publicKey: context.publicKey,
          tokenId: context.tokenId ?? TokenId.default,
          network: context.network,
        },
        action: context.methodName,
        serverNonce: context.nonce?.value ?? Field(0),
      },
    });
  },

  noContext<Output, Inputs extends Record<string, Input>>(
    spec: Spec<Output, Inputs>,
    claims: Claims<Inputs>
  ): NoContextRequest<Output, Inputs> {
    return {
      type: 'no-context',
      spec,
      claims,
      inputContext: undefined,
      deriveContext: () => Field(0),
    };
  },

  toJSON(request: PresentationRequest) {
    let json = {
      type: request.type,
      spec: serializeSpec(request.spec),
      claims: serializeNestedProvableValue(request.claims),
      inputContext: serializeInputContext(request.inputContext),
    };
    return JSON.stringify(json);
  },

  fromJSON<
    R extends RequestFromType<K>,
    K extends PresentationRequestType = PresentationRequestType
  >(expectedType: K, json: string): R {
    let raw: unknown = JSON.parse(json);
    let parsed = PresentationRequestSchema.parse(raw);
    let request = requestFromJson(parsed);
    assert(
      request.type === expectedType,
      `Expected ${expectedType} request, got ${request.type}`
    );
    return request as R;
  },
};

function requestFromJson(
  request: { type: PresentationRequestType } & Record<string, any>
) {
  let spec = deserializeSpec(request.spec);
  let claims = deserializeNestedProvableValue(request.claims);

  switch (request.type) {
    case 'no-context':
      return PresentationRequest.noContext(spec, claims);
    case 'zk-app': {
      const inputContext: any = deserializeInputContext(request.inputContext);
      return ZkAppRequest({ spec, claims, inputContext });
    }
    case 'https': {
      const inputContext: any = deserializeInputContext(request.inputContext);
      return HttpsRequest({ spec, claims, inputContext });
    }
    default:
      throw Error(`Invalid presentation request type: ${request.type}`);
  }
}

type Presentation<
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>
> = {
  version: 'v0';
  claims: Claims<Inputs>;
  outputClaim: Output;
  serverNonce: Field;
  clientNonce: Field;
  proof: { proof: string; maxProofsVerified: number };
};

type Output<R> = R extends PresentationRequest<any, infer O> ? O : never;
type Inputs<R> = R extends PresentationRequest<any, any, infer I> ? I : never;
type WalletContext<R> = R extends PresentationRequest<
  any,
  any,
  any,
  any,
  infer W
>
  ? W
  : never;

const Presentation = {
  async precompile<Output, Inputs extends Record<string, Input>>(
    spec: Spec<Output, Inputs>
  ): Promise<CompiledRequest<Output, Inputs>> {
    let program = createProgram(spec);
    let verificationKey = await program.compile();
    return { spec, program, verificationKey };
  },

  async compile<R extends PresentationRequest>(
    request: R
  ): Promise<
    Omit<R, 'program'> & {
      program: Program<Output<R>, Inputs<R>>;
      verificationKey: VerificationKey;
    }
  > {
    let program: Program<Output<R>, Inputs<R>> = (request as any).program ??
    createProgram(request.spec);
    let verificationKey = await program.compile();
    return { ...request, program, verificationKey };
  },

  /**
   * Create a presentation, given the request, context, and credentials.
   *
   * The first argument is the private key of the credential's owner, which is needed to sign credentials.
   */
  create: createPresentation,

  /**
   * Prepare a presentation, given the request, context, and credentials
   *
   * This way creating the presentation doesn't require the private key of the owner but
   * instead lets the wallet to handle the signing process
   */
  prepare: preparePresentation,

  /**
   * Finalize presentation given request, signature, and prepared data from preparePresentation
   */
  finalize: finalizePresentation,

  /**
   * Verify a presentation against a request and context.
   *
   * Returns the verified output claim of the proof, to be consumed by application-specific logic.
   */
  verify: verifyPresentation,

  /**
   * Serialize a presentation to JSON.
   */
  toJSON,

  /**
   * Deserialize a presentation from JSON.
   */
  fromJSON,
};

async function preparePresentation<R extends PresentationRequest>({
  request,
  context: walletContext,
  credentials,
}: {
  request: R;
  context: WalletContext<R>;
  credentials: (StoredCredential & { key?: string })[];
}): Promise<{
  context: Field;
  messageFields: string[];
  credentialsUsed: Record<string, StoredCredential>;
  serverNonce: Field;
  clientNonce: Field;
  compiledRequest: CompiledRequest<Output<R>, Inputs<R>>;
}> {
  // find credentials
  let { credentialsUsed, credentialsAndSpecs } = pickCredentials(
    request.spec,
    credentials
  );

  // compile the program
  let compiled = await Presentation.precompile(
    request.spec as Spec<Output<R>, Inputs<R>>
  );

  // generate random client nonce
  let clientNonce = Field.random();

  // derive context
  let context = request.deriveContext(request.inputContext, walletContext, {
    clientNonce,
    vkHash: compiled.verificationKey.hash,
    claims: hashClaims(request.claims),
  });

  // prepare fields to sign
  let credHashes = credentialsAndSpecs.map(({ credential }) =>
    hashCredential(credential)
  );
  let issuers = credentialsAndSpecs.map(({ spec, witness }) =>
    spec.issuer(witness)
  );

  // data that is going to be signed by the wallet
  const fieldsToSign = [context, ...zip(credHashes, issuers).flat()];
  return {
    context,
    messageFields: fieldsToSign.map((f) => f.toString()),
    credentialsUsed,
    serverNonce: request.inputContext?.serverNonce ?? Field(0),
    clientNonce,
    compiledRequest: compiled,
  };
}

async function finalizePresentation<R extends PresentationRequest>(
  request: R,
  ownerSignature: Signature,
  preparedData: {
    serverNonce: Field;
    clientNonce: Field;
    context: Field;
    credentialsUsed: Record<string, StoredCredential>;
    compiledRequest: { program: Program<Output<R>, Inputs<R>> };
  }
): Promise<Presentation<Output<R>, Inputs<R>>> {
  // create the presentation proof
  let proof = await preparedData.compiledRequest.program.run({
    context: preparedData.context,
    claims: request.claims as any,
    ownerSignature,
    credentials: preparedData.credentialsUsed as any,
  });
  let { proof: proofBase64, maxProofsVerified } = proof.toJSON();

  return {
    version: 'v0',
    claims: request.claims as any,
    outputClaim: proof.publicOutput,
    serverNonce: preparedData.serverNonce,
    clientNonce: preparedData.clientNonce,
    proof: { maxProofsVerified, proof: proofBase64 },
  };
}

async function createPresentation<R extends PresentationRequest>(
  ownerKey: PrivateKey,
  params: {
    request: R;
    context: WalletContext<R>;
    credentials: (StoredCredential & { key?: string })[];
  }
): Promise<Presentation<Output<R>, Inputs<R>>> {
  const prepared = await preparePresentation(params);
  const ownerSignature = Signature.create(
    ownerKey,
    prepared.messageFields.map(Field.from)
  );
  return finalizePresentation(params.request, ownerSignature, prepared);
}

async function verifyPresentation<R extends PresentationRequest>(
  request: R,
  presentation: Presentation<any, Record<string, any>>,
  context: WalletContext<R>
): Promise<Output<R>> {
  // make sure request is compiled
  let { program, verificationKey } = await Presentation.compile(request);

  // rederive context
  let contextHash = request.deriveContext(request.inputContext, context, {
    clientNonce: presentation.clientNonce,
    vkHash: verificationKey.hash,
    claims: hashClaims(request.claims),
  });

  // assert the correct claims were used, and claims match the proof public inputs
  let { proof, outputClaim } = presentation;
  let claimType = NestedProvable.get(NestedProvable.fromValue(request.claims));
  let claims = request.claims;
  Provable.assertEqual(claimType, presentation.claims, claims);

  // reconstruct proof object
  let inputType = program.program.publicInputType;
  let outputType = program.program.publicOutputType;
  let publicInputFields = inputType.toFields({
    context: contextHash,
    claims: claims as any,
  });
  let publicOutputFields = outputType.toFields(outputClaim);
  let jsonProof: JsonProof = {
    publicInput: publicInputFields.map((f) => f.toString()),
    publicOutput: publicOutputFields.map((f) => f.toString()),
    proof: proof.proof,
    maxProofsVerified: proof.maxProofsVerified as 0 | 1 | 2,
  };

  // verify the proof against our verification key
  let ok = await verify(jsonProof, verificationKey);
  assert(ok, 'Invalid proof');

  // return the verified outputClaim
  return outputClaim;
}

function toJSON<Output, Inputs extends Record<string, Input>>(
  presentation: Presentation<Output, Inputs>
): string {
  let json = {
    version: presentation.version,
    claims: serializeNestedProvableValue(presentation.claims),
    outputClaim: serializeNestedProvableValue(presentation.outputClaim),
    serverNonce: serializeProvable(presentation.serverNonce),
    clientNonce: serializeProvable(presentation.clientNonce),
    proof: presentation.proof,
  };
  return JSON.stringify(json);
}

function fromJSON(presentationJson: string): Presentation {
  let presentation = JSON.parse(presentationJson);
  assert(
    presentation.version === 'v0',
    `Unsupported presentation version: ${presentation.version}`
  );

  return {
    version: presentation.version,
    claims: deserializeNestedProvableValue(presentation.claims),
    outputClaim: deserializeNestedProvableValue(presentation.outputClaim),
    serverNonce: deserializeProvable(presentation.serverNonce),
    clientNonce: deserializeProvable(presentation.clientNonce),
    proof: presentation.proof,
  };
}

// helper

function pickCredentials(
  spec: Spec,
  [...credentials]: (StoredCredential & { key?: string })[]
): {
  credentialsUsed: Record<string, StoredCredential>;
  credentialsAndSpecs: (StoredCredential & { spec: CredentialSpec })[];
} {
  let credentialsNeeded = Object.entries(spec.inputs).filter(
    (c): c is [string, CredentialSpec] => isCredentialSpec(c[1])
  );
  let credentialsUsed: Record<string, StoredCredential> = {};
  let credentialsStillNeeded: [string, CredentialSpec][] = [];

  // an attached `key` signals that the caller knows where to use the credential
  // in that case, we don't perform additional filtering
  for (let [key, spec] of credentialsNeeded) {
    let i = credentials.findIndex((c) => c.key === key);
    if (i === -1) {
      credentialsStillNeeded.push([key, spec]);
      continue;
    } else {
      credentialsUsed[key] = credentials[i]!;
      credentials.splice(i, 1);
    }
  }
  for (let credential of credentials) {
    if (credentialsStillNeeded.length === 0) break;

    // can we use this credential for one of the remaining slots?
    let j = credentialsStillNeeded.findIndex(([, spec]) => {
      let matches = credentialMatchesSpec(spec, credential);
      // console.log('matches', matches, spec, credential);
      return matches;
    });
    if (j === -1) continue;
    let [slot] = credentialsStillNeeded.splice(j, 1);
    let [key] = slot!;
    credentialsUsed[key] = credential;
  }
  assert(
    credentialsStillNeeded.length === 0,
    `Missing credentials: ${credentialsStillNeeded
      .map(([key]) => `"${key}"`)
      .join(', ')}`
  );
  let credentialsAndSpecs = credentialsNeeded.map(([key, spec]) => ({
    ...credentialsUsed[key]!,
    spec,
  }));
  return { credentialsUsed, credentialsAndSpecs };
}

// specific types of requests

type RequestFromType<
  Type extends PresentationRequestType,
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>
> = Type extends 'no-context'
  ? NoContextRequest<Output, Inputs>
  : Type extends 'zk-app'
  ? ZkAppRequest<Output, Inputs>
  : Type extends 'https'
  ? HttpsRequest<Output, Inputs>
  : never;

type NoContextRequest<
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>
> = PresentationRequest<'no-context', Output, Inputs, undefined, undefined>;

type HttpsRequest<
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>
> = PresentationRequest<
  'https',
  Output,
  Inputs,
  HttpsInputContext,
  HttpsWalletContext
>;

type ZkAppRequest<
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>
> = PresentationRequest<'zk-app', Output, Inputs, ZkAppInputContext, undefined>;

function HttpsRequest<Output, Inputs extends Record<string, Input>>(request: {
  spec: Spec<Output, Inputs>;
  claims: Claims<Inputs>;
  inputContext: HttpsInputContext;
  program?: Program<Output, Inputs>;
  verificationKey?: VerificationKey;
}): HttpsRequest<Output, Inputs> {
  return {
    type: 'https',
    ...request,

    deriveContext(inputContext, walletContext, derivedContext) {
      const context = computeHttpsContext({
        ...inputContext,
        ...walletContext,
        ...derivedContext,
      });
      return hashContext(context);
    },
  };
}

function ZkAppRequest<Output, Inputs extends Record<string, Input>>(request: {
  spec: Spec<Output, Inputs>;
  claims: Claims<Inputs>;
  inputContext: ZkAppInputContext;
  program?: Program<Output, Inputs>;
  verificationKey?: VerificationKey;
}): ZkAppRequest<Output, Inputs> {
  return {
    type: 'zk-app',
    ...request,

    deriveContext(inputContext, _walletContext: undefined, derivedContext) {
      const context = computeZkAppContext({
        ...inputContext,
        ...derivedContext,
      });
      return hashContext(context);
    },
  };
}

function hashClaims(claims: Claims<any>) {
  let claimsType = NestedProvable.fromValue(claims);
  let claimsFields = Struct(claimsType).toFields(claims);
  return Poseidon.hash(claimsFields);
}
