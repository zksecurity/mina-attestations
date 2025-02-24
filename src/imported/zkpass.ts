/**
 * This file contains some helpers to wrap zkpass responses in ecdsa credentials.
 *
 * See `ecdsa-credential.test.ts`
 */
import { DynamicBytes, DynamicSHA3 } from '../dynamic.ts';
import { assert, ByteUtils, zip } from '../util.ts';
import {
  EcdsaEthereum,
  getHashHelper,
  parseSignature,
  verifyEthereumSignature,
} from './ecdsa-credential.ts';
import { Credential } from '../credential-index.ts';
import { PublicKey, Bool, Gadgets, Unconstrained } from 'o1js';

export { ZkPass, type ZkPassResponseItem };

const { Signature, Address } = EcdsaEthereum;

const maxMessageLength = 128;
const Message = DynamicBytes({ maxLength: maxMessageLength });

/**
 * Utilities to help process zkpass responses.
 */
const ZkPass = {
  importCredentialPartial,
  encodeParameters,
  genPublicFieldHash,

  CredentialPartial() {
    let cred = ecdsaCredentialsZkPassPartial.get(maxMessageLength);
    cred ??= createCredentialZkPassPartial();
    ecdsaCredentialsZkPassPartial.set(maxMessageLength, cred);
    return cred;
  },

  CredentialFull() {
    let cred = ecdsaCredentialsZkPassFull.get(maxMessageLength);
    cred ??= createCredentialZkPassFull();
    ecdsaCredentialsZkPassFull.set(maxMessageLength, cred);
    return cred;
  },

  async compileDependenciesPartial({ proofsEnabled = true } = {}) {
    await getHashHelper(maxMessageLength).compile({ proofsEnabled });
    let cred = await ZkPass.CredentialPartial();
    await cred.compile({ proofsEnabled });
  },
};

const ecdsaCredentialsZkPassPartial = new Map<
  number,
  ReturnType<typeof createCredentialZkPassPartial>
>();
const ecdsaCredentialsZkPassFull = new Map<
  number,
  ReturnType<typeof createCredentialZkPassFull>
>();

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
  let publicFieldsHash = ZkPass.genPublicFieldHash(
    response.publicFields
  ).toBytes();

  // validate public fields hash
  assert(
    '0x' + ByteUtils.toHex(publicFieldsHash) === response.publicFieldsHash
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

  // compute allocator message hash
  let allocatorMessage = ZkPass.encodeParameters(
    ['bytes32', 'bytes32', 'address'],
    [
      ByteUtils.fromString(response.taskId),
      ByteUtils.fromString(schema),
      ByteUtils.fromHex(response.validatorAddress),
    ]
  );

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
      allocatorMessage,
      allocatorSignature,
      allocatorParityBit,
      allocatorAddress: EcdsaEthereum.Address.from(allocatorAddress),
    },
    privateInput: {
      validatorMessage,
      validatorSignature,
      validatorParityBit,
      validatorAddress: EcdsaEthereum.Address.from(validatorAddress),
    },
  });

  return credential;
}

function createCredentialZkPassPartial() {
  return Credential.Imported.fromMethod(
    {
      name: `ecdsa-partial-${maxMessageLength}`,
      publicInput: {
        allocatorAddress: Address,
        allocatorMessage: Message,
        allocatorSignature: { r: Gadgets.Field3, s: Gadgets.Field3 },
        allocatorParityBit: Bool,
      },
      privateInput: {
        validatorMessage: Message,
        validatorSignature: Signature,
        validatorParityBit: Unconstrained.withEmpty(false),
        validatorAddress: Address,
      },
      data: { allocatorMessage: Message },
    },
    async ({
      publicInput: { allocatorMessage },
      privateInput: {
        validatorMessage,
        validatorSignature,
        validatorParityBit,
        validatorAddress,
      },
    }) => {
      // Verify validator signature
      await verifyEthereumSignature(
        validatorMessage,
        validatorSignature,
        validatorAddress,
        validatorParityBit,
        maxMessageLength
      );

      return { allocatorMessage };
    }
  );
}

// New version - verifies both validator and allocator signatures
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

  const maxMessageLength = 128;

  log('Compiling ZkPass full credential...');
  await EcdsaEthereum.compileDependencies({ maxMessageLength });

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
      name: `ecdsa-full-${maxMessageLength}`,
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
  let arrays = zip(types, values).map(([type, value]) => {
    if (type === 'bytes32') return ByteUtils.padEnd(value, 32, 0);
    if (type === 'address') return ByteUtils.padStart(value, 32, 0);
    throw Error('unexpected type');
  });
  return ByteUtils.concat(...arrays);
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
