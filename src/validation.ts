import { z } from 'zod';

export {
  StoredCredentialSchema,
  PresentationRequestSchema,
  NodeSchema,
  InputSchema,
  ContextSchema,
};

type Literal = string | number | boolean | null;
type Json = Literal | { [key: string]: Json } | Json[];

const LiteralSchema = z.union([z.string(), z.number(), z.boolean(), z.null()]);

const JsonSchema: z.ZodType<Json> = z.lazy(() =>
  z.union([LiteralSchema, z.array(JsonSchema), z.record(JsonSchema)])
);

const PublicKeySchema = z.string().length(55).startsWith('B62');

const SerializedValueSchema = z
  .object({
    _type: z.string(),
    value: JsonSchema,
    properties: z.record(z.any()).optional(),
  })
  .strict();

const SerializedDataValueSchema = z.union([
  SerializedValueSchema,
  z.string(),
  z.number(),
  z.boolean(),
]);

const ProofTypeSchema: z.ZodType<any> = z.lazy(() =>
  z
    .object({
      name: z.string(),
      publicInput: SerializedTypeSchema,
      publicOutput: SerializedTypeSchema,
      maxProofsVerified: z.number(),
      featureFlags: z.record(z.any()),
    })
    .strict()
);

const SerializedTypeSchema: z.ZodType<any> = z.lazy(() =>
  z.union([
    // Basic type
    z
      .object({
        _type: z.string(),
      })
      .strict(),
    // Constant type
    z
      .object({
        type: z.literal('Constant'),
        value: z.string(),
      })
      .strict(),
    // Bytes type
    z
      .object({
        _type: z.literal('Bytes'),
        size: z.number(),
      })
      .strict(),
    // Proof type
    z
      .object({
        _type: z.literal('Proof'),
        proof: ProofTypeSchema,
      })
      .strict(),
    // Array type
    z
      .object({
        _type: z.literal('Array'),
        innerType: SerializedTypeSchema,
        size: z.number(),
      })
      .strict(),
    z
      .object({
        _type: z.literal('Struct'),
        properties: z.record(SerializedTypeSchema),
      })
      .strict(),
    // Allow records of nested types for Struct
    z.record(SerializedTypeSchema),
  ])
);

const SerializedFieldSchema = z
  .object({
    _type: z.literal('Field'),
    value: z.string(),
  })
  .strict();

const SerializedPublicKeySchema = z
  .object({
    _type: z.literal('PublicKey'),
    value: z.string(),
  })
  .strict();

const SerializedPublicKeyTypeSchema = z
  .object({
    _type: z.literal('PublicKey'),
  })
  .strict();

const SerializedSignatureSchema = z
  .object({
    _type: z.literal('Signature'),
    value: z.object({
      r: z.string(),
      s: z.string(),
    }),
  })
  .strict();

// Node schemas

const NodeSchema: z.ZodType<any> = z.lazy(() =>
  z.discriminatedUnion('type', [
    z
      .object({
        type: z.literal('owner'),
      })
      .strict(),

    z
      .object({
        type: z.literal('issuer'),
        credentialKey: z.string(),
      })
      .strict(),

    z
      .object({
        type: z.literal('constant'),
        data: SerializedValueSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('root'),
      })
      .strict(),

    z
      .object({
        type: z.literal('property'),
        key: z.string(),
        inner: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('record'),
        data: z.record(NodeSchema),
      })
      .strict(),

    z
      .object({
        type: z.literal('equals'),
        left: NodeSchema,
        right: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('equalsOneOf'),
        input: NodeSchema,
        options: z.union([
          z.array(NodeSchema), // For array of nodes case
          NodeSchema,
        ]),
      })
      .strict(),

    z
      .object({
        type: z.literal('lessThan'),
        left: NodeSchema,
        right: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('lessThanEq'),
        left: NodeSchema,
        right: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('add'),
        left: NodeSchema,
        right: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('sub'),
        left: NodeSchema,
        right: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('mul'),
        left: NodeSchema,
        right: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('div'),
        left: NodeSchema,
        right: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('and'),
        inputs: z.array(NodeSchema),
      })
      .strict(),

    z
      .object({
        type: z.literal('or'),
        left: NodeSchema,
        right: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('not'),
        inner: NodeSchema,
      })
      .strict(),

    z
      .object({
        type: z.literal('hash'),
        inputs: z.array(NodeSchema),
        prefix: z.union([z.string(), z.null()]).optional(),
      })
      .strict(),

    z
      .object({
        type: z.literal('ifThenElse'),
        condition: NodeSchema,
        thenNode: NodeSchema,
        elseNode: NodeSchema,
      })
      .strict(),
  ])
);

// Input Schema

const InputSchema = z.discriminatedUnion('type', [
  z
    .object({
      type: z.literal('credential'),
      credentialType: z.union([
        z.literal('simple'),
        z.literal('unsigned'),
        z.literal('recursive'),
      ]),
      witness: z.union([z.record(SerializedTypeSchema), SerializedTypeSchema]),
      data: z.union([z.record(SerializedTypeSchema), SerializedTypeSchema]),
    })
    .strict(),

  z
    .object({
      type: z.literal('constant'),
      data: SerializedTypeSchema,
      value: z.union([z.string(), z.record(z.string())]),
    })
    .strict(),

  z
    .object({
      type: z.literal('claim'),
      data: z.union([z.record(SerializedTypeSchema), SerializedTypeSchema]),
    })
    .strict(),
]);

// Context schemas

const HttpsContextSchema = z
  .object({
    type: z.literal('https'),
    action: z.string(),
    serverNonce: SerializedFieldSchema,
  })
  .strict();

const ZkAppContextSchema = z
  .object({
    type: z.literal('zk-app'),
    action: SerializedFieldSchema,
    serverNonce: SerializedFieldSchema,
  })
  .strict();

const ContextSchema = z.union([HttpsContextSchema, ZkAppContextSchema]);

const PresentationRequestSchema = z
  .object({
    type: z.union([
      z.literal('no-context'),
      z.literal('zk-app'),
      z.literal('https'),
    ]),
    spec: z
      .object({
        inputs: z.record(InputSchema),
        logic: z
          .object({
            assert: NodeSchema,
            outputClaim: NodeSchema,
          })
          .strict(),
      })
      .strict(),
    claims: z.record(SerializedValueSchema),
    inputContext: z.union([ContextSchema, z.null()]),
  })
  .strict();

// Witness Schemas

const SimpleWitnessSchema = z
  .object({
    type: z.literal('simple'),
    issuer: SerializedPublicKeySchema,
    issuerSignature: SerializedSignatureSchema,
  })
  .strict();

const RecursiveWitnessSchema = z
  .object({
    type: z.literal('recursive'),
    vk: z
      .object({
        data: z.string(),
        hash: SerializedFieldSchema,
      })
      .strict(),
    proof: z
      .object({
        _type: z.literal('Proof'),
        value: z
          .object({
            publicInput: JsonSchema,
            publicOutput: JsonSchema,
            maxProofsVerified: z.number().min(0).max(2),
            proof: z.string(),
          })
          .strict(),
      })
      .strict(),
  })
  .strict();

const UnsignedWitnessSchema = z
  .object({
    type: z.literal('unsigned'),
  })
  .strict();

const WitnessSchema = z.discriminatedUnion('type', [
  SimpleWitnessSchema,
  RecursiveWitnessSchema,
  UnsignedWitnessSchema,
]);

const SimpleCredentialSchema = z
  .object({
    owner: SerializedPublicKeySchema,
    data: z.record(SerializedDataValueSchema),
  })
  .strict();

const StructCredentialSchema = z
  .object({
    _type: z.literal('Struct'),
    properties: z
      .object({
        owner: SerializedPublicKeyTypeSchema,
        data: JsonSchema,
      })
      .strict(),
    value: z
      .object({
        owner: PublicKeySchema,
        data: JsonSchema,
      })
      .strict(),
  })
  .strict();

const StoredCredentialSchema = z
  .object({
    version: z.literal('v0'),
    witness: WitnessSchema,
    metadata: JsonSchema.optional(),
    credential: z.union([SimpleCredentialSchema, StructCredentialSchema]),
  })
  .strict();

// we could infer the type of StoredCredential from the validation
// type StoredCredential = z.infer<typeof StoredCredentialSchema>;
