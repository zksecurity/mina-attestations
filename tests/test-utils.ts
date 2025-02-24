import { Field, PrivateKey } from 'o1js';
import {
  type Credential,
  type CredentialSpec,
  signCredentials,
} from '../src/credential.ts';

export {
  createOwnerSignature,
  randomPublicKey,
  owner,
  ownerKey,
  issuer,
  issuerKey,
  zkAppAddress,
};

const { publicKey: owner, privateKey: ownerKey } = PrivateKey.randomKeypair();
const { publicKey: issuer, privateKey: issuerKey } = PrivateKey.randomKeypair();
const zkAppAddress = randomPublicKey();

function randomPublicKey() {
  return PrivateKey.random().toPublicKey();
}

function createOwnerSignature<Witness, Data>(
  context: Field,
  ...credentials: [
    CredentialSpec<Witness, Data>,
    { credential: Credential<Data>; witness: Witness }
  ][]
) {
  return signCredentials(
    ownerKey,
    context,
    ...credentials.map(([credentialType, cred]) => ({
      ...cred,
      credentialType,
    }))
  );
}
