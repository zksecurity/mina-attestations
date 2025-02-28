import { Field, PublicKey, Poseidon } from 'o1js';
import { prefixes } from './constants.ts';
import { hashString } from './dynamic/dynamic-hash.ts';

export {
  computeHttpsContext,
  computeZkAppContext,
  hashContext,
  type ZkAppIdentity,
  type NetworkId,
};

type ContextType = 'zk-app' | 'https';

type BaseContext = {
  type: ContextType;
  vkHash: Field;
  clientNonce: Field;
  serverNonce: Field;
  claims: Field;
};

type NetworkId = 'mainnet' | 'devnet' | { custom: string };

type ZkAppIdentity = {
  publicKey: PublicKey;
  tokenId: Field;
  network: NetworkId;
};

type ZkAppContext = BaseContext & {
  type: 'zk-app';
  verifierIdentity: ZkAppIdentity;
  action: string;
};

type HttpsContext = BaseContext & {
  type: 'https';
  verifierIdentity: string;
  action: string;
};

type ContextOutput = {
  type: ContextType;
  vkHash: Field;
  nonce: Field;
  verifierIdentity: Field;
  action: Field;
  claims: Field;
};

function computeNonce(serverNonce: Field, clientNonce: Field): Field {
  return Poseidon.hashWithPrefix(prefixes.nonce, [serverNonce, clientNonce]);
}

function computeHttpsContext(input: Omit<HttpsContext, 'type'>): ContextOutput {
  return {
    type: 'https',
    vkHash: input.vkHash,
    nonce: computeNonce(input.serverNonce, input.clientNonce),
    verifierIdentity: hashString(input.verifierIdentity),
    action: hashString(input.action),
    claims: input.claims,
  };
}

function computeZkAppContext(input: Omit<ZkAppContext, 'type'>): ContextOutput {
  return {
    type: 'zk-app',
    vkHash: input.vkHash,
    nonce: computeNonce(input.serverNonce, input.clientNonce),
    verifierIdentity: hashZkAppIdentity(input.verifierIdentity),
    action: hashString(input.action),
    claims: input.claims,
  };
}

function hashContext(input: ContextOutput): Field {
  return Poseidon.hashWithPrefix(prefixes.context, [
    hashString(input.type),
    input.vkHash,
    input.nonce,
    input.verifierIdentity,
    input.action,
    input.claims,
  ]);
}

function hashZkAppIdentity(identity: ZkAppIdentity): Field {
  return Poseidon.hashWithPrefix(prefixes.zkappIdentity, [
    networkToField(identity.network),
    ...identity.publicKey.toFields(),
    identity.tokenId,
  ]);
}

function networkToField(network: ZkAppIdentity['network']): Field {
  if (network === 'mainnet') return Field(0);
  if (network === 'devnet') return Field(1);
  return hashString(network.custom);
}
