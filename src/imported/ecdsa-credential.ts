import {
  Bytes,
  createEcdsa,
  createForeignCurve,
  Crypto,
  Gadgets,
  Provable,
} from 'o1js';
import { Credential } from '../credential-index.ts';
import { DynamicSHA3, DynamicString } from '../dynamic.ts';

export { EcdsaEthereum };

class PublicKey extends createForeignCurve(Crypto.CurveParams.Secp256k1) {}
class Signature extends createEcdsa(PublicKey) {}

const Bytes32 = Bytes(32);

const EcdsaEthereum = {
  Signature,
  PublicKey,
  Credential: EcdsaCredential,
};

function EcdsaCredential({ maxMessageLength }: { maxMessageLength: number }) {
  const Message = DynamicString({ maxLength: maxMessageLength });
  return Credential.Recursive.fromMethod(
    {
      name: `ecdsa-${maxMessageLength}`,
      publicInput: {
        // this matches the public key type without requiring custom serialization
        signer: { x: { value: Gadgets.Field3 }, y: { value: Gadgets.Field3 } },
      },
      privateInput: { message: Message, signature: Signature },
      data: { message: Message },
    },
    async ({
      publicInput: {
        signer: { x, y },
      },
      privateInput: { message, signature },
    }) => {
      // TODO pass in address instead of signer
      // convert inputs to Secp256k1
      let signer = PublicKey.from({ x: x.value, y: y.value });
      PublicKey.check(signer); // add constraints

      // TODO recursive proof of this
      let messageHash = Provable.witness(Bytes32, () =>
        DynamicSHA3.keccak256(message)
      );

      signature.verifyEthers(messageHash, signer);
      return { message };
    }
  );
}
