/**
 * This file contains some helpers to wrap zkpass responses in ecdsa credentials.
 *
 * See `ecdsa-credential.test.ts`
 */
import { DynamicBytes, DynamicSHA3 } from '../dynamic.ts';
import { assert, ByteUtils, fill, zip } from '../util.ts';
import {
  EcdsaEthereum,
  getHashHelper,
  parseSignature,
  verifyEthereumSignature,
  verifyEthereumSignatureSimple,
} from './ecdsa-credential.ts';
import { Credential } from '../credential-index.ts';
import { PublicKey, Bool, Gadgets, Unconstrained, Bytes, Field } from 'o1js';

export { ZkPass, type ZkPassResponseItem };

const { Signature, Address } = EcdsaEthereum;

const maxMessageLength = 128;
const Message = DynamicBytes({ maxLength: maxMessageLength });
const Bytes32 = Bytes(32);

/**
 * Utilities to help process zkpass responses.
 */
const ZkPass = {
  importCredentialPartial,
  verifyPublicInput,

  encodeParameters,
  genPublicFieldHash,

  CredentialPartial() {
    return (partialCredential ??= createCredentialZkPassPartial());
  },

  CredentialFull() {
    return (fullCredential ??= createCredentialZkPassFull());
  },

  async compileDependenciesPartial({ proofsEnabled = true } = {}) {
    await getHashHelper(maxMessageLength).compile({ proofsEnabled });
    let cred = await ZkPass.CredentialPartial();
    await cred.compile({ proofsEnabled });
  },

  async compileDependenciesFull({ proofsEnabled = true } = {}) {
    await getHashHelper(maxMessageLength).compile({ proofsEnabled });
    let cred = await ZkPass.CredentialFull();
    await cred.compile({ proofsEnabled });
  },
};

let partialCredential:
  | ReturnType<typeof createCredentialZkPassPartial>
  | undefined;
let fullCredential: ReturnType<typeof createCredentialZkPassFull> | undefined;

type Type = 'bytes32' | 'address';

type PublicField = string | ({ [key: string]: PublicField } & { str?: string });

type ZkPassResponseItem = {
  taskId: string;
  publicFields: PublicField[];
  allocatorAddress: string;
  publicFieldsHash: string;
  allocatorSignature: string;
  uHash: string;
  validatorAddress: string;
  validatorSignature: string;
};

async function importCredentialPartial(
  owner: PublicKey,
  schema: string,
  response: ZkPassResponseItem,
  log: (msg: string) => void = () => {}
) {
  // validate public fields hash
  let recoveredPublicFieldsHash = ZkPass.genPublicFieldHash(
    response.publicFields
  ).toBytes();
  assert(
    '0x' + ByteUtils.toHex(recoveredPublicFieldsHash) ===
      response.publicFieldsHash
  );

  let schemaBytes = encodeParameter('bytes32', ByteUtils.fromString(schema));
  let taskId = encodeParameter(
    'bytes32',
    ByteUtils.fromString(response.taskId)
  );
  let uHash = encodeParameter('bytes32', ByteUtils.fromHex(response.uHash));
  let publicFieldsHash = encodeParameter('bytes32', recoveredPublicFieldsHash);

  let { signature: validatorSignature, parityBit: validatorParityBit } =
    parseSignature(response.validatorSignature);
  let validatorAddress = ByteUtils.fromHex(response.validatorAddress);

  let { signature: allocatorSignature, parityBit: allocatorParityBit } =
    parseSignature(response.allocatorSignature);
  let allocatorAddress = ByteUtils.fromHex(response.allocatorAddress);

  log('Compiling ZkPass credential...');
  await ZkPass.compileDependenciesPartial();

  let ZkPassCredential = await ZkPass.CredentialPartial();

  log('Creating ZkPass credential...');
  let credential = await ZkPassCredential.create({
    owner,
    publicInput: {
      schema: Bytes32.from(schemaBytes),
      taskId: Bytes32.from(taskId),
      allocatorAddress: Address.from(allocatorAddress),
      validatorAddress: Address.from(validatorAddress),
      allocatorSignature,
      allocatorParityBit,
    },
    privateInput: {
      publicFieldsHash: Bytes32.from(publicFieldsHash),
      uHash: Bytes32.from(uHash),
      validatorSignature,
      validatorParityBit,
    },
  });

  return credential;
}

type Field3 = [Field, Field, Field];

/**
 * Verify the public input of a partial zkpass credential.
 *
 * Returns the allocator address and schema id for further verification against
 * expected values.
 *
 * This is a verification step that can be done in the clear, and is
 * outsourced from the proof to the verifier.
 */
function verifyPublicInput(publicInput: {
  schema: Bytes;
  taskId: Bytes;
  validatorAddress: Bytes;
  allocatorAddress: Bytes;
  allocatorSignature: { r: Field3; s: Field3 };
  allocatorParityBit: Bool;
}) {
  let allocatorMessage = DynamicBytes.from([
    ...publicInput.taskId.bytes,
    ...publicInput.schema.bytes,
    ...fill(12, 0x00), // 12 zero bytes to fill up address
    ...publicInput.validatorAddress.bytes,
  ]);

  verifyEthereumSignatureSimple(
    allocatorMessage,
    Signature.from(publicInput.allocatorSignature),
    publicInput.allocatorAddress,
    Unconstrained.from(publicInput.allocatorParityBit.toBoolean())
  );

  return {
    allocatorAddress: publicInput.allocatorAddress.toHex(),
    schema: ByteUtils.toString(publicInput.schema.toBytes()),
  };
}

function createCredentialZkPassPartial() {
  return Credential.Imported.fromMethod(
    {
      name: `zkpass-partial-${maxMessageLength}`,
      publicInput: {
        schema: Bytes32,
        taskId: Bytes32,
        validatorAddress: Address,
        allocatorAddress: Address,
        allocatorSignature: { r: Gadgets.Field3, s: Gadgets.Field3 },
        allocatorParityBit: Bool,
      },
      privateInput: {
        uHash: Bytes32,
        publicFieldsHash: Bytes32,
        validatorSignature: Signature,
        validatorParityBit: Unconstrained.withEmpty(false),
      },
      data: { nullifier: Bytes32, publicFieldsHash: Bytes32 },
    },
    async ({
      publicInput: { schema, taskId, validatorAddress },
      privateInput: {
        uHash,
        publicFieldsHash,
        validatorSignature,
        validatorParityBit,
      },
    }) => {
      // combine inputs to validator message
      let validatorMessage = DynamicBytes.from([
        ...taskId.bytes,
        ...schema.bytes,
        ...uHash.bytes,
        ...publicFieldsHash.bytes,
      ]);

      // Verify validator signature
      await verifyEthereumSignature(
        validatorMessage,
        validatorSignature,
        validatorAddress,
        validatorParityBit,
        maxMessageLength
      );

      return { nullifier: uHash, publicFieldsHash };
    }
  );
}

// Verifies both validator and allocator signatures
async function importCredentialFull(
  owner: PublicKey,
  schema: string,
  response: ZkPassResponseItem,
  log: (msg: string) => void = () => {}
) {
  let publicFieldsHash = ZkPass.genPublicFieldHash(
    response.publicFields
  ).toBytes();

  // validate public fields hash
  assert(
    '0x' + ByteUtils.toHex(publicFieldsHash) === response.publicFieldsHash
  );

  // compute allocator message hash
  let allocatorMessage = ZkPass.encodeParameters(
    ['bytes32', 'bytes32', 'address'],
    [
      ByteUtils.fromString(response.taskId),
      ByteUtils.fromString(schema),
      ByteUtils.fromHex(response.validatorAddress),
    ]
  );

  // compute validator message hash
  let validatorMessage = ZkPass.encodeParameters(
    ['bytes32', 'bytes32', 'bytes32', 'bytes32'],
    [
      ByteUtils.fromString(response.taskId),
      ByteUtils.fromString(schema),
      ByteUtils.fromHex(response.uHash),
      publicFieldsHash,
    ]
  );

  let { signature: allocatorSignature, parityBit: allocatorParityBit } =
    parseSignature(response.allocatorSignature);
  let { signature: validatorSignature, parityBit: validatorParityBit } =
    parseSignature(response.validatorSignature);
  let allocatorAddress = ByteUtils.fromHex(response.allocatorAddress);
  let validatorAddress = ByteUtils.fromHex(response.validatorAddress);

  log('Compiling ZkPass full credential...');
  await ZkPass.compileDependenciesFull();
  let ZkPassCredential = await ZkPass.CredentialFull();

  log('Creating ZkPass full credential...');
  let credential = await ZkPassCredential.create({
    owner,
    publicInput: {
      allocatorAddress: EcdsaEthereum.Address.from(allocatorAddress),
    },
    privateInput: {
      allocatorMessage,
      allocatorSignature,
      allocatorParityBit,
      validatorMessage,
      validatorSignature,
      validatorParityBit,
      validatorAddress: EcdsaEthereum.Address.from(validatorAddress),
    },
  });

  return credential;
}

// Verifies both validator and allocator signatures
// TODO: OOM
function createCredentialZkPassFull() {
  return Credential.Imported.fromMethod(
    {
      name: `zkpass-full-${maxMessageLength}`,
      publicInput: { allocatorAddress: Address },
      privateInput: {
        allocatorMessage: Message,
        allocatorSignature: Signature,
        allocatorParityBit: Unconstrained.withEmpty(false),
        validatorMessage: Message,
        validatorSignature: Signature,
        validatorParityBit: Unconstrained.withEmpty(false),
        validatorAddress: Address,
      },
      data: { allocatorMessage: Message, validatorMessage: Message },
    },
    async ({
      publicInput: { allocatorAddress },
      privateInput: {
        allocatorMessage,
        allocatorSignature,
        allocatorParityBit,
        validatorMessage,
        validatorSignature,
        validatorParityBit,
        validatorAddress,
      },
    }) => {
      // Verify allocator signature
      await verifyEthereumSignature(
        allocatorMessage,
        allocatorSignature,
        allocatorAddress,
        allocatorParityBit,
        maxMessageLength
      );

      // Verify validator signature
      await verifyEthereumSignature(
        validatorMessage,
        validatorSignature,
        validatorAddress,
        validatorParityBit,
        maxMessageLength
      );

      return { allocatorMessage, validatorMessage };
    }
  );
}

function encodeParameters(types: Type[], values: Uint8Array[]) {
  let arrays = zip(types, values).map(([type, value]) =>
    encodeParameter(type, value)
  );
  return ByteUtils.concat(...arrays);
}

function encodeParameter(type: Type, value: Uint8Array) {
  if (type === 'bytes32') return ByteUtils.padEnd(value, 32, 0);
  if (type === 'address') return ByteUtils.padStart(value, 32, 0);
  throw Error('unexpected type');
}

// hash used by zkpass to commit to public fields
// FIXME unfortunately this does nothing to prevent collisions -.-
function genPublicFieldHash(publicFields: PublicField[]) {
  let publicData = publicFields.map((item) => {
    if (typeof item === 'object') delete item.str;
    return item;
  });

  let values: string[] = [];

  function recurse(obj: PublicField) {
    if (typeof obj === 'string') {
      values.push(obj);
      return;
    }
    for (let key in obj) {
      if (obj.hasOwnProperty(key)) {
        if (typeof obj[key] === 'object' && obj[key] !== null) {
          recurse(obj[key]); // it's a nested object, so we do it again
        } else {
          values.push(obj[key]!); // it's not an object, so we just push the value
        }
      }
    }
  }
  publicData.forEach((data) => recurse(data));

  let publicFieldStr = values.join('');
  if (publicFieldStr === '') publicFieldStr = '1'; // ??? another deliberate collision

  return DynamicSHA3.keccak256(publicFieldStr);
}
