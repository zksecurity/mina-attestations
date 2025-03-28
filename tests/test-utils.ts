import { PrivateKey, TokenId } from 'o1js';
import type { ZkAppIdentity } from '../src/context.ts';

export {
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
