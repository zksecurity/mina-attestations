import { createEcdsa, createForeignCurve, Crypto, UInt8 } from 'o1js';
import { DynamicArray } from './dynamic-array.ts';
import { notImplemented } from '../util.ts';
import { DynamicString } from './dynamic-string.ts';
import { DynamicSHA3 } from './dynamic-sha3.ts';
import { toDecimalString } from './gadgets-digits.ts';

export { EcdsaEthereum };

class Secp256k1 extends createForeignCurve(Crypto.CurveParams.Secp256k1) {}
class EcdsaSignature extends createEcdsa(Secp256k1) {}

const EcdsaEthereum = {
  Signature: EcdsaSignature,
  PublicKey: Secp256k1,

  verify: verifyEthereumSignature,

  Recursive: {
    verify: notImplemented,
  },
};

// Ethereum-specific prefix for signing
const messagePrefix = '\x19Ethereum Signed Message:\n';

function verifyEthereumSignature(
  message: DynamicArray<UInt8> | string,
  signature: EcdsaSignature,
  publicKey: Secp256k1
) {
  message = DynamicString.from(message);

  // encode message by prepending Ethereum prefix and encoded message length
  let encodedMessage = DynamicString.from(messagePrefix)
    // note: 5 decimal digits are enough because DynamicString only supports length < 2^16
    .concat(toDecimalString(message.length, 5))
    .concat(message);

  // hash message using dynamic Keccak256
  let hash = DynamicSHA3.keccak256(encodedMessage);

  // verify signature on hash
  let ok = signature.verifySignedHash(hash, publicKey);
  ok.assertTrue('signature is invalid');
}
