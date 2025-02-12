/**
 * This file contains some helpers to wrap zkpass responses in ecdsa credentials.
 *
 * See `ecdsa-credential.test.ts`
 */
import { PublicKey } from 'o1js';
import { DynamicSHA3 } from '../dynamic.ts';
import { assert, ByteUtils, zip } from '../util.ts';
import { EcdsaEthereum, parseSignature } from './ecdsa-credential.ts';

export { ZkPass, type ZkPassResponseItem };

/**
 * Utitilies to help process zkpass responses.
 */
const ZkPass = {
  importCredentialPartial,
  encodeParameters,
  genPublicFieldHash,
};

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

  const maxMessageLength = 128;

  log('Compiling ZkPass credential...');
  await EcdsaEthereum.compileDependencies({ maxMessageLength });

  let EcdsaCredentialPartial = await EcdsaEthereum.CredentialZkPassPartial({
    maxMessageLength,
  });

  log('Creating ZkPass credential...');
  let credential = await EcdsaCredentialPartial.create({
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

  let EcdsaCredentialFull = await EcdsaEthereum.CredentialZkPassFull({
    maxMessageLength,
  });

  log('Creating ZkPass full credential...');
  let credential = await EcdsaCredentialFull.create({
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
