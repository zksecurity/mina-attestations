import { Field, PublicKey, Poseidon } from 'o1js';
import { prefixes } from './constants.ts';
import { hashString } from './dynamic/dynamic-hash.ts';
import {
  deserializeProvable,
  serializeProvable,
  type SerializedValue,
} from './serialize-provable.ts';
import { assert } from './util.ts';

export {
  computeHttpsContext,
  computeZkAppContext,
  hashContext,
  serializeInputContext,
  deserializeHttpsContext,
  deserializeZkAppContext,
  type ZkAppIdentity,
  type NetworkId,
  type ZkAppInputContext,
  type ZkAppContext,
  type HttpsInputContext,
  type HttpsWalletContext,
  type HttpsContext,
  type WalletDerivedContext,
};

type ContextType = 'zk-app' | 'https';

type BaseContext = {
  type: ContextType;
  vkHash: Field;
  clientNonce: Field;
  serverNonce: Field;
  claims: Field;
};

type BaseInputContext = {
  action: string;
  serverNonce: Field;
};

type HttpsInputContext = BaseInputContext & {
  type: 'https';
};

type NetworkId = 'mainnet' | 'devnet' | { custom: string };

type ZkAppIdentity = {
  publicKey: PublicKey;
  tokenId: Field;
  network: NetworkId;
};

type ZkAppInputContext = BaseInputContext & {
  type: 'zk-app';
  verifierIdentity: ZkAppIdentity;
};

type HttpsWalletContext = {
  verifierIdentity: string;
};
type WalletDerivedContext = {
  vkHash: Field;
  claims: Field;
  clientNonce: Field;
};

type ZkAppContext = ZkAppInputContext & WalletDerivedContext;

type HttpsContext = HttpsInputContext &
  HttpsWalletContext &
  WalletDerivedContext;

// type-level assertions
true satisfies ZkAppContext extends BaseContext ? true : false;
true satisfies HttpsContext extends BaseContext ? true : false;

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

function computeHttpsContext(input: HttpsContext): ContextOutput {
  return {
    type: input.type,
    vkHash: input.vkHash,
    nonce: computeNonce(input.serverNonce, input.clientNonce),
    verifierIdentity: hashString(input.verifierIdentity),
    action: hashString(input.action),
    claims: input.claims,
  };
}

function computeZkAppContext(input: ZkAppContext): ContextOutput {
  return {
    type: input.type,
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

// serialization

type SerializedHttpsContext = {
  type: 'https';
  action: string;
  serverNonce: SerializedValue;
};
type SerializedZkAppContext = {
  type: 'zk-app';
  action: string;
  serverNonce: SerializedValue;
  verifierIdentity: {
    publicKey: SerializedValue;
    tokenId: SerializedValue;
    network: 'mainnet' | 'devnet' | { custom: string };
  };
};
type SerializedContext = SerializedHttpsContext | SerializedZkAppContext | null;

function serializeInputContext(
  context: undefined | ZkAppInputContext | HttpsInputContext
): SerializedContext {
  if (context === undefined) return null;
  let serverNonce = serializeProvable(context.serverNonce);
  if (context.type === 'https') {
    return { type: context.type, serverNonce, action: context.action };
  }
  if (context.type === 'zk-app') {
    let { publicKey, tokenId, network } = context.verifierIdentity;
    return {
      type: context.type,
      serverNonce,
      action: context.action,
      verifierIdentity: {
        publicKey: serializeProvable(publicKey),
        tokenId: serializeProvable(tokenId),
        network,
      },
    };
  }
  throw Error(
    `Unsupported context type: ${(context satisfies never as any).type}`
  );
}

function deserializeHttpsContext(
  context: SerializedContext
): HttpsInputContext {
  assert(context?.type === 'https');
  return {
    type: context.type,
    action: context.action,
    serverNonce: deserializeProvable(context.serverNonce),
  };
}

function deserializeZkAppContext(
  context: SerializedContext
): ZkAppInputContext {
  assert(context?.type === 'zk-app');
  return {
    type: context.type,
    action: context.action,
    serverNonce: deserializeProvable(context.serverNonce),
    verifierIdentity: {
      publicKey: deserializeProvable(context.verifierIdentity.publicKey),
      tokenId: deserializeProvable(context.verifierIdentity.tokenId),
      network: context.verifierIdentity.network,
    },
  };
}
