import { assert, ByteUtils } from '../../util.ts';
import { EcdsaEthereum, parseSignature } from '../ecdsa-credential.ts';
import { owner } from '../../../tests/test-utils.ts';
import { PublicKey } from 'o1js';
import { ZkPass, type ZkPassResponseItem } from '../zkpass.ts';
import { Credential } from '../../credential-index.ts';

console.time('compile dependencies');
await ZkPass.compileDependenciesPartial({ proofsEnabled: true });
console.timeEnd('compile dependencies');

console.time('zkpass create credential');
const ZkPassCredentialPartial = await ZkPass.CredentialPartial();
console.timeEnd('zkpass create credential');

console.time('zkpass compile');
let vk = await ZkPassCredentialPartial.compile();
console.timeEnd('zkpass compile');
console.log('vk.hash:', vk.hash.toJSON());

// create zkpass cred from zkpass data
const schema = 'c7eab8b7d7e44b05b41b613fe548edf5';

const response: ZkPassResponseItem = {
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
};

let publicFieldsHash = ZkPass.genPublicFieldHash(
  response.publicFields
).toBytes();

// validate public fields hash
assert('0x' + ByteUtils.toHex(publicFieldsHash) === response.publicFieldsHash);

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

let { signature: validatorSignature, parityBit: validatorParityBit } =
  parseSignature(response.validatorSignature);
let validatorAddress = ByteUtils.fromHex(response.validatorAddress);
let { signature: allocatorSignature, parityBit: allocatorParityBit } =
  parseSignature(response.allocatorSignature);
let allocatorAddress = ByteUtils.fromHex(response.allocatorAddress);

console.time('zkpass constraints (recursive)');
let csRec = (await ZkPassCredentialPartial.program.analyzeMethods()).run;
console.log(csRec.summary());
console.timeEnd('zkpass constraints (recursive)');

console.time('zkpass prove');
let credential = await ZkPassCredentialPartial.create({
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
console.timeEnd('zkpass prove');

console.log(
  'zkpasstest::credential.witness.vk.hash:',
  credential.witness.vk.hash.toJSON()
);

let json = Credential.toJSON(credential);
let recovered = await Credential.fromJSON(json);
await Credential.validate(recovered);

/******************************************/
const cred = await ZkPass.importCredentialPartial(
  PublicKey.fromBase58(
    'B62qmb5sdmFDTDi63wHk2S4GLu5tN2Rofrjp9HwdPPNGUgUGv21GEUi'
  ),
  schema,
  response
);

console.log('zkpasstest::cred.witness.vk.hash:', cred.witness.vk.hash.toJSON());
console.log('zkpasstest::Credential.toJSON(cred):', Credential.toJSON(cred));
