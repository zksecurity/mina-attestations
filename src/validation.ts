import { record, z } from 'zod';
import type {
  SerializedNestedType,
  SerializedType,
} from './serialize-provable.ts';

export {
  StoredCredentialSchema,
  PresentationRequestSchema,
  NodeSchema,
  InputSchema,
  ContextSchema,
  PresentationSchema,
};
export type {
  InputJSON,
  ConstantInputJSON,
  ImportedWitnessSpecJSON,
  CredentialSpecJSON,
  NodeJSON,
  SpecJSON,
  PresentationRequestJSON,
  StoredCredentialJSON,
  ContextJSON,
  ZkAppIdentityJSON,
  PresentationJSON,
};

type Literal = string | number | boolean | null;
type Json = Literal | { [key: string]: Json } | Json[];

const LiteralSchema = z.union([z.string(), z.number(), z.boolean(), z.null()]);

const JsonSchema: z.ZodType<Json> = z.lazy(() =>
  z.union([LiteralSchema, z.array(JsonSchema), z.record(JsonSchema)])
);

const PublicKeySchema = z.string().length(55).startsWith('B62');

const maxProofsVerified = z.union([z.literal(0), z.literal(1), z.literal(2)]);
const booleanOrNull = z.boolean().or(z.null());
const featureFlags = z.object({
  rangeCheck0: booleanOrNull,
  rangeCheck1: booleanOrNull,
  foreignFieldAdd: booleanOrNull,
  foreignFieldMul: booleanOrNull,
  xor: booleanOrNull,
  rot: booleanOrNull,
  lookup: booleanOrNull,
  runtimeTables: booleanOrNull,
});

const ProofTypeSchema: z.ZodType<{
  name: string;
  publicInput: SerializedType;
  publicOutput: SerializedType;
  maxProofsVerified: z.infer<typeof maxProofsVerified>;
  featureFlags: z.infer<typeof featureFlags>;
}> = z.lazy(() =>
  z
    .object({
      name: z.string(),
      publicInput: SerializedTypeSchema,
      publicOutput: SerializedTypeSchema,
      maxProofsVerified,
      featureFlags,
    })
    .strict()
);

const SerializedTypeSchema: z.ZodType<SerializedType> = z.lazy(() =>
  z.union([
    // Basic type
    z.object({
      _type: z.union([
        z.literal('Field'),
        z.literal('Bool'),
        z.literal('UInt8'),
        z.literal('UInt32'),
        z.literal('UInt64'),
        z.literal('Int64'),
        z.literal('PublicKey'),
        z.literal('Signature'),
        z.literal('Undefined'),
        z.literal('VerificationKey'),
      ]),
    }),
    // Constant type
    z.object({
      _type: z.literal('Constant'),
      value: JsonSchema,
    }),
    // Bytes type
    z.object({
      _type: z.literal('Bytes'),
      size: z.number(),
    }),
    // Proof type
    z.object({
      _type: z.literal('Proof'),
      proof: ProofTypeSchema,
    }),
    // Array type
    z.object({
      _type: z.literal('Array'),
      inner: SerializedTypeSchema,
      size: z.number(),
    }),
    // Struct type
    z.object({
      _type: z.literal('Struct'),
      properties: record(NestedSerializedTypeSchema),
    }),
    // Factory
    z.object({
      _type: z.string(),
      _isFactory: z.literal(true),
      maxLength: z.number().optional(),
      maxEntries: z.number().optional(),
      innerType: z.lazy(() => SerializedTypeSchema).optional(),
      knownShape: z.record(z.lazy(() => SerializedTypeSchema)).optional(),
    }),
  ])
);

const NestedSerializedTypeSchema: z.ZodType<SerializedNestedType> = z.lazy(() =>
  z.union([z.record(NestedSerializedTypeSchema), SerializedTypeSchema])
);

const SerializedValueSchema = SerializedTypeSchema.and(
  z.object({ value: JsonSchema })
);

const SerializedDataValueSchema = z.union([
  SerializedValueSchema,
  z.string(),
  z.number(),
  z.boolean(),
]);

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
type NodeJSON =
  | { type: 'owner' }
  | { type: 'credential'; credentialKey: string }
  | { type: 'issuer'; credentialKey: string }
  | { type: 'issuerPublicKey'; credentialKey: string }
  | { type: 'verificationKeyHash'; credentialKey: string }
  | { type: 'publicInput'; credentialKey: string }
  | { type: 'constant'; data: z.infer<typeof SerializedValueSchema> }
  | { type: 'root' }
  | { type: 'property'; key: string; inner: NodeJSON }
  | { type: 'record'; data: Record<string, NodeJSON> }
  | { type: 'equals'; left: NodeJSON; right: NodeJSON }
  | { type: 'equalsOneOf'; input: NodeJSON; options: NodeJSON[] | NodeJSON }
  | { type: 'lessThan'; left: NodeJSON; right: NodeJSON }
  | { type: 'lessThanEq'; left: NodeJSON; right: NodeJSON }
  | { type: 'add'; left: NodeJSON; right: NodeJSON }
  | { type: 'sub'; left: NodeJSON; right: NodeJSON }
  | { type: 'mul'; left: NodeJSON; right: NodeJSON }
  | { type: 'div'; left: NodeJSON; right: NodeJSON }
  | { type: 'and'; inputs: NodeJSON[] }
  | { type: 'or'; left: NodeJSON; right: NodeJSON }
  | { type: 'not'; inner: NodeJSON }
  | { type: 'hash'; inputs: NodeJSON[]; prefix?: string | null }
  | {
      type: 'ifThenElse';
      condition: NodeJSON;
      thenNode: NodeJSON;
      elseNode: NodeJSON;
    };

const NodeSchema: z.ZodType<NodeJSON> = z.lazy(() =>
  z.discriminatedUnion('type', [
    z
      .object({ type: z.literal('constant'), data: SerializedValueSchema })
      .strict(),
    z.object({ type: z.literal('root') }).strict(),
    z.object({ type: z.literal('owner') }).strict(),
    z
      .object({
        type: z.literal('credential'),
        credentialKey: z.string(),
        credentialType: z.string(),
      })
      .strict(),
    z.object({ type: z.literal('issuer'), credentialKey: z.string() }).strict(),
    z
      .object({ type: z.literal('issuerPublicKey'), credentialKey: z.string() })
      .strict(),
    z
      .object({
        type: z.literal('verificationKeyHash'),
        credentialKey: z.string(),
      })
      .strict(),
    z
      .object({ type: z.literal('publicInput'), credentialKey: z.string() })
      .strict(),

    z
      .object({
        type: z.literal('property'),
        key: z.string(),
        inner: NodeSchema,
      })
      .strict(),

    z
      .object({ type: z.literal('record'), data: z.record(NodeSchema) })
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

const importedWitnessSpec = z.object({
  type: z.literal('imported'),
  publicInputType: SerializedTypeSchema,
  publicOutputType: SerializedTypeSchema,
  maxProofsVerified,
  featureFlags,
});
type ImportedWitnessSpecJSON = z.infer<typeof importedWitnessSpec>;

const credentialSpec = z
  .object({
    type: z.literal('credential'),
    credentialType: z.union([
      z.literal('native'),
      z.literal('unsigned'),
      z.literal('imported'),
    ]),
    witness: importedWitnessSpec.or(z.null()),
    data: NestedSerializedTypeSchema,
  })
  .strict();
type CredentialSpecJSON = z.infer<typeof credentialSpec>;

const ConstantInputSchema = z
  .object({
    type: z.literal('constant'),
    data: SerializedTypeSchema,
    value: JsonSchema,
  })
  .strict();
type ConstantInputJSON = z.infer<typeof ConstantInputSchema>;

const InputSchema = z.discriminatedUnion('type', [
  credentialSpec,
  ConstantInputSchema,
  z
    .object({
      type: z.literal('claim'),
      data: NestedSerializedTypeSchema,
    })
    .strict(),
]);

type InputJSON = z.infer<typeof InputSchema>;

const spec = z
  .object({
    inputs: z.record(InputSchema),
    assert: NodeSchema,
    outputClaim: NodeSchema,
  })
  .strict();

type SpecJSON = z.infer<typeof spec>;

// Context schemas

const httpsContext = z
  .object({
    type: z.literal('https'),
    action: z.string(),
    serverNonce: SerializedFieldSchema,
  })
  .strict();

const networkId = z.union([
  z.literal('mainnet'),
  z.literal('devnet'),
  z.object({ custom: z.string() }),
]);
const zkAppIdentity = z
  .object({
    publicKey: SerializedPublicKeySchema,
    tokenId: SerializedFieldSchema,
    network: networkId,
  })
  .strict();

type ZkAppIdentityJSON = z.infer<typeof zkAppIdentity>;

const zkAppContext = z
  .object({
    type: z.literal('zk-app'),
    action: z.string(),
    serverNonce: SerializedFieldSchema,
    verifierIdentity: zkAppIdentity,
  })
  .strict();

const ContextSchema = z.union([httpsContext, zkAppContext, z.null()]);

type ContextJSON = z.infer<typeof ContextSchema>;

// Presentation Request Schema

const PresentationRequestSchema = z
  .object({
    type: z.union([
      z.literal('no-context'),
      z.literal('zk-app'),
      z.literal('https'),
    ]),
    spec,
    claims: z.record(SerializedValueSchema),
    inputContext: ContextSchema,
  })
  .strict();

type PresentationRequestJSON = z.infer<typeof PresentationRequestSchema>;

// Witness Schemas

const NativeWitnessSchema = z
  .object({
    type: z.literal('native'),
    issuer: SerializedPublicKeySchema,
    issuerSignature: SerializedSignatureSchema,
  })
  .strict();

const verificationKey = z
  .object({ data: z.string(), hash: SerializedFieldSchema })
  .strict()
  .or(
    z.object({
      _type: z.literal('VerificationKey'),
      value: z.object({ data: z.string(), hash: z.string() }),
    })
  );

const ImportedWitnessSchema = z
  .object({
    type: z.literal('imported'),
    vk: verificationKey,
    proof: z
      .object({
        _type: z.literal('Proof'),
        proof: ProofTypeSchema,
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
  NativeWitnessSchema,
  ImportedWitnessSchema,
  UnsignedWitnessSchema,
]);

const NativeCredentialSchema = z
  .object({
    owner: SerializedPublicKeySchema,
    data: z.record(SerializedDataValueSchema),
  })
  .strict();

const StructCredentialSchema = z
  .object({
    _type: z.literal('Struct'),
    properties: z.object({
      owner: SerializedPublicKeyTypeSchema,
      data: NestedSerializedTypeSchema,
    }),
    value: z
      .object({
        owner: z.object({
          _type: z.literal('PublicKey'),
          value: PublicKeySchema,
        }),
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
    credential: z.union([NativeCredentialSchema, StructCredentialSchema]),
  })
  .strict();

type StoredCredentialJSON = z.infer<typeof StoredCredentialSchema>;

// presentation

const PresentationSchema = z
  .object({
    version: z.literal('v0'),
    claims: z.record(SerializedValueSchema),
    outputClaim: SerializedValueSchema,
    serverNonce: SerializedFieldSchema,
    clientNonce: SerializedFieldSchema,
    proof: z.object({
      maxProofsVerified,
      proof: z.string(),
    }),
  })
  .strict();

type PresentationJSON = z.infer<typeof PresentationSchema>;
