import {
  DynamicProof,
  FeatureFlags,
  Field,
  type JsonProof,
  Poseidon,
  PrivateKey,
  Provable,
  ProvableType,
  PublicKey,
  Signature,
  Struct,
  TokenId,
  UInt32,
  Unconstrained,
  VerificationKey,
  verify,
} from 'o1js';
import {
  Spec,
  type Input,
  type Claims,
  isCredentialSpec,
  type PublicInputs,
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
  serializeInputContext,
  deserializeHttpsContext,
  deserializeZkAppContext,
} from './context.ts';
import { NestedProvable } from './nested.ts';
import { serializeSpec, deserializeSpec } from './serialize-spec.ts';
import {
  deserializeNestedProvableValue,
  deserializeProvableValue,
  serializeProvableValue,
  serializeProvableField,
  serializeSimplyNestedProvableValue,
} from './serialize-provable.ts';
import {
  type PresentationJSON,
  type PresentationRequestJSON,
  PresentationRequestSchema,
  PresentationSchema,
} from './validation.ts';
import { TypeBuilder } from './provable-type-builder.ts';

// external API
export {
  PresentationRequest,
  HttpsRequest,
  ZkAppRequest,
  Presentation,
  ProvablePresentation,
};

// internal
export { type PresentationRequestType, pickCredentials };

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

  ProvablePresentation: typeof ProvablePresentation<Output, Inputs> & {
    from(input: Presentation): ProvablePresentation<Output, Inputs>;

    provable: Provable<
      ProvablePresentation<Output, Inputs>,
      Presentation<Output, Inputs>
    >;
  };
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
          network: context.network ?? 'devnet',
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
      network?: NetworkId;
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
          network: context.network ?? 'devnet',
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
    let json: PresentationRequestJSON = {
      type: request.type,
      spec: serializeSpec(request.spec),
      claims: serializeSimplyNestedProvableValue(request.claims),
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

function requestFromJson(request: PresentationRequestJSON) {
  let spec = deserializeSpec(request.spec);
  let claims = deserializeNestedProvableValue(request.claims);

  switch (request.type) {
    case 'no-context':
      return PresentationRequest.noContext(spec, claims);
    case 'zk-app': {
      const inputContext = deserializeZkAppContext(request.inputContext);
      return ZkAppRequest({ spec, claims, inputContext });
    }
    case 'https': {
      const inputContext = deserializeHttpsContext(request.inputContext);
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
  proof: { proof: string; maxProofsVerified: 0 | 1 | 2 };
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
    let maxProofsVerified = await program.program.maxProofsVerified();
    // TODO this is extra work and should be exposed on ZkProgram
    let featureFlags = await FeatureFlags.fromZkProgram(program.program);

    let compiled = {
      claimsType: program.claimsType,
      outputClaimType: program.outputClaimType,
      tagName: program.program.name,
      verificationKey,
      maxProofsVerified,
      featureFlags,
    };

    class Presentation_ extends ProvablePresentation<Output, Inputs> {
      compiledRequest() {
        return compiled;
      }
      static from(input: Presentation<Output, Inputs>) {
        return this.provable.fromValue(input);
      }

      static get provable(): Provable<
        ProvablePresentation<Output, Inputs>,
        Presentation<Output, Inputs>
      > {
        return super.provable;
      }
    }

    return {
      spec,
      program,
      verificationKey,
      ProvablePresentation: Presentation_,
    };
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

// json

function toJSON<Output, Inputs extends Record<string, Input>>(
  presentation: Presentation<Output, Inputs>
): string {
  let json: PresentationJSON = {
    version: presentation.version,
    claims: serializeSimplyNestedProvableValue(presentation.claims),
    outputClaim: serializeProvableValue(presentation.outputClaim),
    serverNonce: serializeProvableField(presentation.serverNonce),
    clientNonce: serializeProvableField(presentation.clientNonce),
    proof: presentation.proof,
  };
  return JSON.stringify(json);
}

function fromJSON(presentationJson: string): Presentation {
  let parsed: unknown = JSON.parse(presentationJson);
  let presentation = PresentationSchema.parse(parsed);
  assert(
    presentation.version === 'v0',
    `Unsupported presentation version: ${presentation.version}`
  );
  return {
    version: presentation.version,
    claims: deserializeNestedProvableValue(presentation.claims),
    outputClaim: deserializeProvableValue(presentation.outputClaim),
    serverNonce: deserializeProvableValue(presentation.serverNonce),
    clientNonce: deserializeProvableValue(presentation.clientNonce),
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

function hashClaimsFromType<T>(claimsType: ProvableType<T>, claims: T) {
  let claimsFields = ProvableType.get(claimsType).toFields(claims);
  return Poseidon.hash(claimsFields);
}

// in-circuit verification and provable type

/**
 * Presentation that can be verified inside a zkApp.
 *
 * Create a subclass for your presentation as follows:
 *
 * ```ts
 * let compiled = await Presentation.precompile(spec);
 * class ProvablePresentation extends compiled.ProvablePresentation {}
 * ```
 */
class ProvablePresentation<
  Output = any,
  Inputs extends Record<string, Input> = any
> {
  // properties created from a presentation
  claims: Claims<Inputs>;
  outputClaim: Output;
  clientNonce: Field;
  serverNonce: Unconstrained<bigint>;
  proof: Unconstrained<string>;

  constructor(input: {
    claims: Claims<Inputs>;
    outputClaim: Output;
    clientNonce: Field;
    serverNonce: Unconstrained<bigint>;
    proof: Unconstrained<string>;
  }) {
    this.claims = input.claims;
    this.outputClaim = input.outputClaim;
    this.clientNonce = input.clientNonce;
    this.serverNonce = input.serverNonce;
    this.proof = input.proof;
  }

  // static properties derived from precompiling the request
  compiledRequest(): {
    claimsType: ProvableType<Claims<Inputs>>;
    outputClaimType: ProvableType<Output>;

    tagName: string;
    verificationKey: VerificationKey;
    maxProofsVerified: 0 | 1 | 2;
    featureFlags: FeatureFlags;
  } {
    throw Error('Must be implemented in subclass');
  }

  /**
   * Verify presentation in a provable context.
   *
   * Input is the zkApp which this presentation is verified in.
   *
   * Pass in the public key, token id and current method of your zkapp to make sure
   * you don't accept presentations that were intended for a different context.
   *
   * Optionally, you can further restrict context by passing in the network and nonce.
   */
  verify(context: {
    publicKey: PublicKey;
    tokenId: Field;
    methodName: string;
    network?: NetworkId;
    nonce?: UInt32;
  }): { claims: Claims<Inputs>; outputClaim: Output } {
    // input/output types
    let compiled = this.compiledRequest();
    let { claimsType, outputClaimType } = compiled;
    let { claims, outputClaim } = this;

    // rederive context
    let fullContext = computeZkAppContext({
      type: 'zk-app',
      verifierIdentity: {
        publicKey: context.publicKey,
        tokenId: context.tokenId,
        network: context.network ?? 'devnet',
      },
      action: context.methodName,
      serverNonce: context.nonce?.value ?? Field(0),
      clientNonce: this.clientNonce,
      vkHash: compiled.verificationKey.hash,
      claims: hashClaimsFromType(claimsType, claims),
    });
    let contextHash = hashContext(fullContext);

    // reconstruct proof class
    // TODO there should be DynamicProof.fromProgram()
    class PresentationProof extends DynamicProof<PublicInputs<Inputs>, Output> {
      static publicInputType = NestedProvable.get({
        context: Field,
        claims: claimsType,
      });
      static publicOutputType = ProvableType.get(outputClaimType);
      static maxProofsVerified = compiled.maxProofsVerified;
      static featureFlags = compiled.featureFlags;

      static tag() {
        return { name: compiled.tagName };
      }
    }

    // witness proof and mark it to be verified
    let presentationProof: DynamicProof<
      PublicInputs<Inputs>,
      Output
    > = Provable.witness(PresentationProof, () => {
      return {
        proof: DynamicProof._proofFromBase64(
          this.proof.get(),
          compiled.maxProofsVerified
        ),
        maxProofsVerified: compiled.maxProofsVerified,
        publicInput: {
          context: contextHash.toConstant(),
          claims: Provable.toConstant(claimsType, claims),
        },
        publicOutput: Provable.toConstant(outputClaimType, this.outputClaim),
      };
    });
    presentationProof.declare();
    presentationProof.verify(compiled.verificationKey);

    // check public inputs
    Provable.assertEqual(
      claimsType,
      presentationProof.publicInput.claims,
      claims
    );
    presentationProof.publicInput.context.assertEquals(contextHash);
    Provable.assertEqual(
      outputClaimType,
      presentationProof.publicOutput,
      outputClaim
    );

    // return the verified claims
    return { claims, outputClaim };
  }

  // provable type representation
  static get provable(): Provable<
    ProvablePresentation,
    Presentation<any, any>
  > {
    let This = this;
    let { claimsType, outputClaimType, maxProofsVerified } =
      this.prototype.compiledRequest();
    return TypeBuilder.shape({
      claims: claimsType,
      outputClaim: outputClaimType,
      clientNonce: Field,
      serverNonce: Unconstrained.withEmpty(0n),
      proof: Unconstrained.withEmpty(''),
    })
      .forClass(This)
      .mapValue<Presentation>({
        there(p): Presentation {
          return {
            version: 'v0',
            claims: ProvableType.get(claimsType).fromValue(p.claims),
            outputClaim: ProvableType.get(outputClaimType).fromValue(
              p.outputClaim
            ),
            clientNonce: Field(p.clientNonce),
            serverNonce: Field(p.serverNonce),
            proof: { proof: p.proof, maxProofsVerified },
          };
        },
        back(p) {
          return {
            claims: ProvableType.get(claimsType).toValue(p.claims),
            outputClaim: ProvableType.get(outputClaimType).toValue(
              p.outputClaim
            ),
            clientNonce: p.clientNonce.toBigInt(),
            serverNonce: p.serverNonce.toBigInt(),
            proof: p.proof.proof,
          };
        },
        distinguish(p) {
          return p instanceof This;
        },
      })
      .build();
  }
}
