import { assert } from '../util.ts';

const { Buffer } = require('buffer');
const secp256k1 = require('secp256k1');
const { keccak256 } = require('js-sha3');

// sample generated using the front-end-JS-SDK
// TODO why do we care about the publicFieldsHash and uHash? what are they hashes of?
const sampleProof = [
  {
    taskId: '1582fa3c0e9747f0beebc0540052278d',
    publicFields: [],
    allocatorAddress: '0x19a567b3b212a5b35bA0E3B600FbEd5c2eE9083d',
    publicFieldsHash:
      '0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6',
    allocatorSignature:
      '0x84de522ac578d25a50e70b54f403dad02347679ddacb88974a37df758042fe441c8dc34869f2f05bd300062127e75d3b135147f890a704c9db6422607c0485ca1b',
    uHash: '0x2bed950239c116cecdbc4e65a16401c2f6c45cdf305bda5fe963ac8f1f1c51d0',
    validatorAddress: '0xb1C4C1E1Cdd5Cf69E27A3A08C8f51145c2E12C6a',
    validatorSignature:
      '0x99d61fa8f8413a3eaa38d2c064119c67592c696a0b8c2c2eb4a9b2e4ef122de3674e68203d0388d238635e36237f41279a406512515f6a26b0b38479d5c6eade1b',
  },
];

const schema = 'c7eab8b7d7e44b05b41b613fe548edf5';

const {
  taskId,
  uHash,
  publicFieldsHash,
  validatorSignature: signature,
  validatorAddress: originAddress,
} = sampleProof[0]!;

const isValid = verifyECDSASignature({
  taskId,
  schema,
  uHash,
  publicFieldsHash,
  signature,
  originAddress,
});
assert(isValid);

type Type = 'bytes32' | 'address';

function verifyECDSASignature({
  taskId,
  schema,
  uHash,
  publicFieldsHash,
  signature,
  originAddress,
  recipient,
}: {
  taskId: string;
  schema: string;
  uHash: string;
  publicFieldsHash: string;
  signature: string;
  originAddress: string;
  recipient?: string;
}) {
  const types: Type[] = ['bytes32', 'bytes32', 'bytes32', 'bytes32'];
  const values = [
    stringToHex(taskId),
    stringToHex(schema),
    uHash,
    publicFieldsHash,
  ];

  if (recipient) {
    types.push('address');
    values.push(recipient);
  }

  const encodeParams = encodeParameters(types, values);

  const paramsHash = soliditySha3(encodeParams);

  // Ethereum signed message hash (EIP-191)
  const PREFIX = '\x19Ethereum Signed Message:\n32';
  const messageHash = hexToUint8Array(paramsHash);
  const prefixedMessage = Buffer.concat([
    Buffer.from(PREFIX),
    Buffer.from(messageHash),
  ]);
  const finalHash = keccak256(prefixedMessage);

  // Parse signature components
  const signatureBytes = hexToUint8Array(signature);
  const r = signatureBytes.slice(0, 32);
  const s = signatureBytes.slice(32, 64);
  const v = signatureBytes[64]!;

  // Convert v to recovery id (27/28 -> 0/1)
  const recoveryId = v - 27;
  if (recoveryId !== 0 && recoveryId !== 1) {
    throw Error(`Invalid recovery id: ${recoveryId}`);
  }

  // Recover the public key
  const pubKey = secp256k1.ecdsaRecover(
    Buffer.concat([r, s]),
    recoveryId,
    Buffer.from(finalHash, 'hex'),
    false
  );

  // Convert public key to address
  // The address is the last 20 bytes of the public key's keccak256 hash
  // It is generated from the uncompressed public key
  // We also have to remove the prefix 0x04 from the public key
  const pubKeyHash = keccak256(Buffer.from(pubKey.slice(1)));
  const address = '0x' + pubKeyHash.slice(-40);

  return address.toLowerCase() === originAddress.toLowerCase();
}

// Web3.js adds 0x to the beginning of the hex string
function stringToHex(str: string) {
  return '0x' + Buffer.from(str, 'utf8').toString('hex');
}

// Based on the Solidity ABI encoding we have the following definitions for encoding bytes32 and address
// For any ABI value X, we recursively define enc(X), depending on the type of X being
// bytes<M>: enc(X) is the sequence of bytes in X padded with trailing zero-bytes to a length of 32 bytes.
// address: as in the uint160 case
// uint<M>: enc(X) is the big-endian encoding of X, padded on the higher-order (left) side with zero-bytes such that the length is 32 bytes.
// https://docs.soliditylang.org/en/latest/abi-spec.html#formal-specification-of-the-encoding
function encodeParameters(types: Type[], values: string[]) {
  return (
    '0x' +
    types
      .map((type, index) => {
        if (type === 'bytes32') {
          return values[index]!.replace(/^0x/, '').padEnd(64, '0');
        } else if (type === 'address') {
          return values[index]!.replace(/^0x/, '')
            .toLowerCase()
            .padStart(64, '0');
        } else {
          throw Error(
            `Expected type to be either bytes32 or address, instead received: ${type}`
          );
        }
      })
      .join('')
  );
}

// Will calculate the sha3 of given input parameters in the same way solidity would.
// This means arguments will be ABI converted and tightly packed before being hashed.
// String: HEX string with leading 0x is interpreted as bytes.
// https://web3js.readthedocs.io/en/v1.2.11/web3-utils.html#soliditysha3
function soliditySha3(encodeParams: string) {
  // If it's empty, return undefined to match Web3.js behavior
  if (!encodeParams || encodeParams === '0x') throw Error('Invalid inputs');
  const bytes = Buffer.from(encodeParams.replace('0x', ''), 'hex');
  return '0x' + keccak256(bytes);
}

function hexToUint8Array(hex: string) {
  return new Uint8Array(
    hex.startsWith('0x')
      ? hex
          .slice(2)
          .match(/.{1,2}/g)!
          .map((byte) => parseInt(byte, 16))
      : []
  );
}

module.exports = {
  verifyECDSASignature,
  stringToHex,
  encodeParameters,
  soliditySha3,
};
