/**
 * This example shows how to turn an ethers.js signature into an ECDSA credential.
 */
import { Credential, DynamicBytes } from 'mina-attestations';
import { EcdsaEthereum } from 'mina-attestations/imported';
import { PrivateKey, Bytes } from 'o1js';
import { Wallet } from 'ethers/wallet';
import { id } from 'ethers/hash';

// consts
const maxMessageLength = 32;
const proofsEnabled = false;
const Message = DynamicBytes({ maxLength: maxMessageLength });

// prepare ecdsa credential
await EcdsaEthereum.compileDependencies({ maxMessageLength, proofsEnabled });
const EcdsaCredential = await EcdsaEthereum.Credential({ maxMessageLength });
await EcdsaCredential.compile({ proofsEnabled });

// wallets
let { publicKey: minaPubKey } = PrivateKey.randomKeypair();
let signer = new Wallet(id('test'));

// signature
let message = 'abc';
const parseHex = (hex: string) => Bytes.fromHex(hex.slice(2)).toBytes();
const hashMessage = (msg: string) => parseHex(id(msg));
let sig = await signer.signMessage(hashMessage(message));

// create credential (which verifies the signature)
let { signature, parityBit } = EcdsaEthereum.parseSignature(sig);

let credential = await EcdsaCredential.create({
  owner: minaPubKey,
  publicInput: { signerAddress: EcdsaEthereum.parseAddress(signer.address) },
  privateInput: { message: Message.fromString(message), signature, parityBit },
});
console.log(
  '✅ created credential',
  Credential.toJSON(credential).slice(0, 1000) + '...'
);
