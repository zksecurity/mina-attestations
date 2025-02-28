import { Field, PrivateKey, TokenId } from 'o1js';
import {
  type Credential,
  type CredentialSpec,
  signCredentials,
} from '../src/credential.ts';
import type { ZkAppIdentity } from '../src/context.ts';

export {
  createOwnerSignature,
  randomPublicKey,
  owner,
  ownerKey,
  issuer,
  issuerKey,
  zkAppAddress,
  zkAppIdentity,
};

const { publicKey: owner, privateKey: ownerKey } = PrivateKey.randomKeypair();
const { publicKey: issuer, privateKey: issuerKey } = PrivateKey.randomKeypair();

const zkAppAddress = randomPublicKey();
const zkAppIdentity: ZkAppIdentity = {
  publicKey: zkAppAddress,
  tokenId: TokenId.default,
  network: 'devnet',
};

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
