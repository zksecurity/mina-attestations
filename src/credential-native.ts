/**
 * Native signature credential
 */
import { Field, Poseidon, PrivateKey, PublicKey, Signature } from 'o1js';
import {
  type StoredCredential,
  type Credential,
  hashCredential,
  type CredentialSpec,
} from './credential.ts';
import {
  inferNestedProvable,
  type InferNestedProvable,
  NestedProvable,
} from './nested.ts';
import { prefixes } from './constants.ts';
import { ProvableType } from './o1js-missing.ts';
import { deserializeNestedProvableValue } from './serialize-provable.ts';
import type { Json } from './types.ts';

export { Native, createNative, type NativeWitness };

type NativeWitness = {
  type: 'native';
  issuer: PublicKey;
  issuerSignature: Signature;
};

type Native<Data> = StoredCredential<Data, NativeWitness>;

const NativeBase = {
  credentialType: 'native' as const,

  witness: undefined,
  witnessType() {
    return {
      type: ProvableType.constant('native' as const),
      issuer: PublicKey,
      issuerSignature: Signature,
    };
  },

  // verify the signature
  verify({ issuer, issuerSignature }: NativeWitness, credHash: Field) {
    let ok = issuerSignature.verify(issuer, [credHash]);
    ok.assertTrue('Invalid signature');
  },

  async validate({ issuer, issuerSignature }: NativeWitness, credHash: Field) {
    let ok = issuerSignature.verify(issuer, [credHash]);
    ok.assertTrue('Invalid signature');
  },

  // issuer == issuer public key
  issuer({ issuer }: NativeWitness) {
    return Poseidon.hashWithPrefix(prefixes.issuerNative, issuer.toFields());
  },

  matchesSpec(witness: NativeWitness) {
    return witness.type === 'native';
  },
};

function Native<DataType extends NestedProvable>(
  dataType: DataType
): CredentialSpec<NativeWitness, InferNestedProvable<DataType>> {
  return { ...NativeBase, data: inferNestedProvable(dataType) };
}
Native.issuer = function (issuer: PublicKey) {
  return Poseidon.hashWithPrefix(prefixes.issuerNative, issuer.toFields());
};

function createNative<Data>(
  issuerPrivateKey: PrivateKey,
  credentialInput: Credential<Data> | string,
  metadata?: Json
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
    metadata,
    credential,
  };
}
