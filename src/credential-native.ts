/**
 * Native signature credential
 */
import { Poseidon, PrivateKey, PublicKey, Signature } from 'o1js';
import {
  type StoredCredential,
  type Credential,
  defineCredential,
  hashCredential,
} from './credential.ts';
import { NestedProvable } from './nested.ts';
import { prefixes } from './constants.ts';
import { ProvableType } from './o1js-missing.ts';
import { deserializeNestedProvableValue } from './serialize-provable.ts';

export { Native, createNative, type Witness, type Metadata };

type Witness = {
  type: 'native';
  issuer: PublicKey;
  issuerSignature: Signature;
};

// TODO
type Metadata = undefined;

type Native<Data> = StoredCredential<Data, Witness, Metadata>;

const Native = Object.assign(
  defineCredential({
    credentialType: 'native',
    witness: {
      type: ProvableType.constant('native' as const),
      issuer: PublicKey,
      issuerSignature: Signature,
    },

    // verify the signature
    verify({ issuer, issuerSignature }, credHash) {
      let ok = issuerSignature.verify(issuer, [credHash]);
      ok.assertTrue('Invalid signature');
    },
    async verifyOutsideCircuit({ issuer, issuerSignature }, credHash) {
      let ok = issuerSignature.verify(issuer, [credHash]);
      ok.assertTrue('Invalid signature');
    },

    // issuer == issuer public key
    issuer({ issuer }) {
      return Poseidon.hashWithPrefix(prefixes.issuerNative, issuer.toFields());
    },

    matchesSpec(witness) {
      return witness.type === 'native';
    },
  }),
  {
    issuer(issuer: PublicKey) {
      return Poseidon.hashWithPrefix(prefixes.issuerNative, issuer.toFields());
    },
  }
);

function createNative<Data>(
  issuerPrivateKey: PrivateKey,
  credentialInput: Credential<Data> | string
): Native<Data> {
  let issuer = issuerPrivateKey.toPublicKey();
  let credential =
    typeof credentialInput === 'string'
      ? deserializeNestedProvableValue(JSON.parse(credentialInput))
      : credentialInput;
  let credHash = hashCredential(credential);
  let issuerSignature = Signature.create(issuerPrivateKey, [credHash]);

  return {
    version: 'v0',
    witness: { type: 'native', issuer, issuerSignature },
    metadata: undefined,
    credential,
  };
}
