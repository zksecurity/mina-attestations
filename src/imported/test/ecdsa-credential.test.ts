import { assert, ByteUtils } from '../../util.ts';
import {
  EcdsaEthereum,
  getHashHelper,
  parseSignature,
  verifyEthereumSignatureSimple,
} from '../ecdsa-credential.ts';
import { owner } from '../../../tests/test-utils.ts';
import { Provable, Unconstrained } from 'o1js';
import { DynamicBytes } from '../../dynamic.ts';
import { ZkPass, type ZkPassResponseItem } from '../zkpass.ts';
import { Credential } from '../../credential-index.ts';

const proofsEnabled = false;

const maxMessageLength = 128;
const Message = DynamicBytes({ maxLength: maxMessageLength });

console.time('hash helper constraints');
let { short: shortCs } = await getHashHelper(maxMessageLength).analyzeMethods();
console.log(shortCs.summary());
console.timeEnd('hash helper constraints');

console.time('compile dependencies');
await EcdsaEthereum.compileDependencies({
  maxMessageLength,
  proofsEnabled,
});
console.timeEnd('compile dependencies');

console.time('ecdsa create credential');
const EcdsaCredential = await EcdsaEthereum.Credential({ maxMessageLength });
console.timeEnd('ecdsa create credential');

console.time('ecdsa compile');
let vk = await EcdsaCredential.compile({ proofsEnabled });
console.timeEnd('ecdsa compile');

// create ecdsa cred from zkpass data
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

// compute message hash
let message = ZkPass.encodeParameters(
  ['bytes32', 'bytes32', 'bytes32', 'bytes32'],
  [
    ByteUtils.fromString(response.taskId),
    ByteUtils.fromString(schema),
    ByteUtils.fromHex(response.uHash),
    publicFieldsHash,
  ]
);
console.log('message length', message.length);

let { signature, parityBit } = parseSignature(response.validatorSignature);
let address = ByteUtils.fromHex(response.validatorAddress);

function simpleCircuit() {
  let messageVar = Provable.witness(Message, () => message);
  let signatureVar = Provable.witness(EcdsaEthereum.Signature, () => signature);
  let addressVar = Provable.witness(EcdsaEthereum.Address, () =>
    EcdsaEthereum.Address.from(address)
  );
  let parityBitVar = Unconstrained.witness(() => parityBit);

  verifyEthereumSignatureSimple(
    messageVar,
    signatureVar,
    addressVar,
    parityBitVar
  );
}

// plain
simpleCircuit();

// witgen
await Provable.runAndCheck(simpleCircuit);

console.time('ecdsa constraints (simple)');
let cs = await Provable.constraintSystem(simpleCircuit);
console.log(cs.summary());
console.timeEnd('ecdsa constraints (simple)');

console.time('ecdsa constraints (recursive)');
let csRec = (await EcdsaCredential.program.analyzeMethods()).run;
console.log(csRec.summary());
console.timeEnd('ecdsa constraints (recursive)');

console.time('ecdsa prove');
let credential = await EcdsaCredential.create({
  owner,
  publicInput: { signerAddress: EcdsaEthereum.Address.from(address) },
  privateInput: { message, signature, parityBit },
});
console.timeEnd('ecdsa prove');

let json = Credential.toJSON(credential);
let recovered = await Credential.fromJSON(json);

if (proofsEnabled) await Credential.validate(recovered);
