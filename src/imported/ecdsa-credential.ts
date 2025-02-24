import {
  Bool,
  Bytes,
  createEcdsa,
  createForeignCurve,
  Crypto,
  EcdsaSignature,
  Experimental,
  Field,
  type From,
  Gadgets,
  Keccak,
  Provable,
  UInt8,
  Unconstrained,
  ZkProgram,
} from 'o1js';
import { Credential } from '../credential-index.ts';
import { DynamicArray, DynamicBytes, DynamicSHA3 } from '../dynamic.ts';
import { bytesToBigintBE } from '../rsa/utils.ts';
import { assert, ByteUtils } from '../util.ts';
import { unpackBytes } from '../dynamic/gadgets.ts';

export {
  EcdsaEthereum,
  parseSignature,
  recoverPublicKey,
  publicKeyToAddress,
  verifyEthereumSignature,
  verifyEthereumSignatureSimple,
  getHashHelper,
};

class PublicKey extends createForeignCurve(Crypto.CurveParams.Secp256k1) {}
class Signature extends createEcdsa(PublicKey) {}

const MessageHash = Bytes(32);
const Address = Bytes(20);

/**
 * Ethereum-style ECDSA signature credentials.
 */
const EcdsaEthereum = {
  Signature,
  PublicKey,
  MessageHash,
  Address,

  /**
   * Credential that wraps an Ethereum-style ECDSA signature.
   */
  Credential({ maxMessageLength }: { maxMessageLength: number }) {
    let cred = ecdsaCredentials.get(maxMessageLength);
    cred ??= createCredential({ maxMessageLength });
    ecdsaCredentials.set(maxMessageLength, cred);
    return cred;
  },

  CredentialZkPassPartial({ maxMessageLength }: { maxMessageLength: number }) {
    let cred = ecdsaCredentialsZkPassPartial.get(maxMessageLength);
    cred ??= createCredentialZkPassPartial({ maxMessageLength });
    ecdsaCredentialsZkPassPartial.set(maxMessageLength, cred);
    return cred;
  },

  CredentialZkPassFull({ maxMessageLength }: { maxMessageLength: number }) {
    let cred = ecdsaCredentialsZkPassFull.get(maxMessageLength);
    cred ??= createCredentialZkPassFull({ maxMessageLength });
    ecdsaCredentialsZkPassFull.set(maxMessageLength, cred);
    return cred;
  },

  compileDependencies,
};

const ecdsaCredentials = new Map<number, ReturnType<typeof createCredential>>();
const ecdsaCredentialsZkPassPartial = new Map<
  number,
  ReturnType<typeof createCredentialZkPassPartial>
>();
const ecdsaCredentialsZkPassFull = new Map<
  number,
  ReturnType<typeof createCredentialZkPassFull>
>();
const hashHelpers = new Map<number, ReturnType<typeof createHashHelper>>();

function createCredential(options: { maxMessageLength: number }) {
  let { maxMessageLength } = options;
  const Message = DynamicBytes({ maxLength: maxMessageLength });
  return Credential.Imported.fromMethod(
    {
      name: `ecdsa-${maxMessageLength}`,
      publicInput: { signerAddress: Address },
      privateInput: {
        message: Message,
        signature: Signature,
        parityBit: Unconstrained.withEmpty(false),
      },
      data: { message: Message },
    },
    async ({
      publicInput: { signerAddress },
      privateInput: { message, signature, parityBit },
    }) => {
      await verifyEthereumSignature(
        message,
        signature,
        signerAddress,
        parityBit,
        maxMessageLength
      );
      return { message };
    }
  );
}

function createCredentialZkPassPartial(options: { maxMessageLength: number }) {
  let { maxMessageLength } = options;
  const Message = DynamicBytes({ maxLength: maxMessageLength });
  return Credential.Imported.fromMethod(
    {
      name: `ecdsa-partial-${maxMessageLength}`,
      publicInput: {
        allocatorAddress: Address,
        allocatorMessage: Message,
        allocatorSignature: { r: Gadgets.Field3, s: Gadgets.Field3 },
        allocatorParityBit: Bool,
      },
      privateInput: {
        validatorMessage: Message,
        validatorSignature: Signature,
        validatorParityBit: Unconstrained.withEmpty(false),
        validatorAddress: Address,
      },
      data: { allocatorMessage: Message },
    },
    async ({
      publicInput: { allocatorMessage },
      privateInput: {
        validatorMessage,
        validatorSignature,
        validatorParityBit,
        validatorAddress,
      },
    }) => {
      // Verify validator signature
      await verifyEthereumSignature(
        validatorMessage,
        validatorSignature,
        validatorAddress,
        validatorParityBit,
        maxMessageLength
      );

      return { allocatorMessage };
    }
  );
}

// Verifies both validator and allocator signatures
// TODO: OOM
function createCredentialZkPassFull(options: { maxMessageLength: number }) {
  let { maxMessageLength } = options;
  const Message = DynamicBytes({ maxLength: maxMessageLength });
  return Credential.Imported.fromMethod(
    {
      name: `ecdsa-full-${maxMessageLength}`,
      publicInput: { allocatorAddress: Address },
      privateInput: {
        allocatorMessage: Message,
        allocatorSignature: Signature,
        allocatorParityBit: Unconstrained.withEmpty(false),
        validatorMessage: Message,
        validatorSignature: Signature,
        validatorParityBit: Unconstrained.withEmpty(false),
        validatorAddress: Address,
      },
      data: { allocatorMessage: Message, validatorMessage: Message },
    },
    async ({
      publicInput: { allocatorAddress },
      privateInput: {
        allocatorMessage,
        allocatorSignature,
        allocatorParityBit,
        validatorMessage,
        validatorSignature,
        validatorParityBit,
        validatorAddress,
      },
    }) => {
      // Verify allocator signature
      await verifyEthereumSignature(
        allocatorMessage,
        allocatorSignature,
        allocatorAddress,
        allocatorParityBit,
        maxMessageLength
      );

      // Verify validator signature
      await verifyEthereumSignature(
        validatorMessage,
        validatorSignature,
        validatorAddress,
        validatorParityBit,
        maxMessageLength
      );

      return { allocatorMessage, validatorMessage };
    }
  );
}

/**
 * Compile the ECDSA credential for the given message length and its ZkProgram dependencies.
 */
async function compileDependencies({
  maxMessageLength,
  proofsEnabled = true,
}: {
  maxMessageLength: number;
  proofsEnabled?: boolean;
}) {
  await getHashHelper(maxMessageLength).compile({ proofsEnabled });
  let cred = await EcdsaEthereum.Credential({ maxMessageLength });
  await cred.compile({ proofsEnabled });
}

// Ethereum signed message hash (EIP-191), assuming a 32-byte message that resulted from another hash
const MESSAGE_PREFIX = '\x19Ethereum Signed Message:\n32';

/**
 * Recursive ethereum-style signature verification.
 *
 * - The message is hashed in two steps, first a normal message hash (using Keccak) and then final EIP-191 hash.
 * - The public key is recovered from the message, signature and parity bit. It is shown to be correct by hashing to the signer address.
 * - The method returns nothing, and fails if the signature is invalid.
 */
async function verifyEthereumSignature(
  message: DynamicArray<UInt8>,
  signature: Signature,
  signerAddress: Bytes,
  parityBit: Unconstrained<boolean>,
  maxMessageLength: number
) {
  // in a recursive call, hash the message and extract the public key
  const hashHelper = getHashHelper(maxMessageLength);
  const hashHelperRecursive = Experimental.Recursive(hashHelper);
  let messageHash = await hashHelperRecursive.short(message);

  // witness the recovered public key
  let publicKey = Provable.witness(PublicKey, () =>
    recoverPublicKey(messageHash, signature, parityBit.get())
  );

  // check that public key hashes to address
  let recoveredAddress = publicKeyToAddress(publicKey);
  Provable.assertEqual(Address, recoveredAddress, signerAddress);

  // verify the signature against the now-validated public key
  let ok = signature.verifySignedHash(messageHash, publicKey);
  ok.assertTrue('signature is invalid');
  return { message };
}

/**
 * Non-recursive e2e signature verification, for benchmarking and testing.
 *
 * Note: this is not provable due to the circuit limit, use the recursive version for that.
 */
function verifyEthereumSignatureSimple(
  message: DynamicArray<UInt8>,
  signature: Signature,
  signerAddress: Bytes,
  parityBit: Unconstrained<boolean>
) {
  // hash the message
  let messageHash = DynamicSHA3.keccak256(message);
  let finalHash = Keccak.ethereum([
    ...Bytes.fromString(MESSAGE_PREFIX).bytes,
    ...messageHash.bytes,
  ]);

  // witness the recovered public key
  let publicKey = Provable.witness(PublicKey, () =>
    recoverPublicKey(finalHash, signature, parityBit.get())
  );

  // check that public key hashes to address
  let recoveredAddress = publicKeyToAddress(publicKey);
  Provable.assertEqual(Address, recoveredAddress, signerAddress);

  // verify the signature against the now-validated public key
  let ok = signature.verifySignedHash(finalHash, publicKey);
  ok.assertTrue('signature is invalid');
}

// helper functions

function publicKeyToAddress(pk: From<typeof PublicKey>) {
  let { x, y } = PublicKey.from(pk);

  // convert both x and y to 32-byte big-endian integers
  let xBytes = foreignFieldToBytes32BE(x);
  let yBytes = foreignFieldToBytes32BE(y);

  // hash the concatenation of x and y
  // and take the last 20 bytes as the address
  let pkHash = Keccak.ethereum([...xBytes, ...yBytes]);
  return Address.from(pkHash.bytes.slice(-20));
}

/**
 * Convert 3x88-bit foreign field to 32 big-endian bytes.
 * Asserts that the 33th byte is zero.
 */
function foreignFieldToBytes32BE(field: { value: [Field, Field, Field] }) {
  let [x0, x1, x2] = field.value;
  let bytes0 = unpackBytes(x0, 11);
  let bytes1 = unpackBytes(x1, 11);
  let bytes2 = unpackBytes(x2, 11);
  let extraByte = bytes2.pop()!;
  extraByte.assertEquals(0, 'Foreign field exceeds 32 bytes');
  // since big-endian is expected, we reverse the bytes
  return [...bytes0, ...bytes1, ...bytes2].reverse();
}

/**
 * Recover the implied public key from a message hash, signature and a parity bit.
 */
function recoverPublicKey(
  messageHash: Bytes | Uint8Array,
  signature: From<typeof EcdsaSignature>,
  isOdd: boolean
) {
  let {
    Scalar: { Bigint: Scalar },
    Field: { Bigint: Field },
    Bigint: Curve,
  } = EcdsaEthereum.PublicKey;

  // read inputs
  if (messageHash instanceof Bytes.Base) messageHash = messageHash.toBytes();
  if (!(signature instanceof EcdsaEthereum.Signature))
    signature = EcdsaEthereum.Signature.from(signature);

  let m = Scalar.mod(bytesToBigintBE(messageHash));
  let r = signature.r.toBigInt();
  let s = signature.s.toBigInt();

  // first, recover R_y from R_x and parity
  let x = Field.mod(r);
  let x3 = Field.mul(x, Field.square(x));
  let y2 = Field.add(x3, Field.mul(Curve.a, x) + Curve.b);
  let y = Field.sqrt(y2);
  assert(y !== undefined);
  if (Field.isEven(y) !== !isOdd) y = Field.negate(y);
  let R = { x, y, infinity: false };

  // recover public key
  let rInv = Scalar.inverse(r);
  assert(rInv !== undefined);

  let publicKey = Curve.sub(
    Curve.scale(R, Scalar.mul(s, rInv)),
    Curve.scale(Curve.one, Scalar.mul(m, rInv))
  );
  assert(publicKey.infinity === false);
  return publicKey;
}

/**
 * Input can be a hex string or a Uint8Array.
 */
function parseSignature(signature: string | Uint8Array) {
  if (typeof signature === 'string') signature = ByteUtils.fromHex(signature);
  assert(signature.length === 65);

  let r = bytesToBigintBE(signature.slice(0, 32));
  let s = bytesToBigintBE(signature.slice(32, 64));
  let v = signature[64]!;
  assert(v === 27 || v === 28, `Invalid recovery id "v" ${v}`);

  // Convert v to parity of R_y (27/28 -> 0/1 -> boolean)
  let parityBit = !!(v - 27);
  return { signature: { r, s }, parityBit };
}

/*
RECURSIVE PROOF SPLITTING

there are two versions, an easy one that only supports messages up to a few keccak blocks,
and a flexible and more complex one.

VERSION 1:

(main) ---- (hash message hash and message)

VERSION 2, with two recursive branches:

(main) ---- (hash message hash and message)
       \--- (hash message hash and end of message) --> (recursive message hash)
*/

function getHashHelper(maxMessageLength: number) {
  if (!hashHelpers.has(maxMessageLength)) {
    hashHelpers.set(maxMessageLength, createHashHelper(maxMessageLength));
  }
  return hashHelpers.get(maxMessageLength)!;
}

function createHashHelper(maxMessageLength: number) {
  const Message = DynamicArray(UInt8, { maxLength: maxMessageLength });

  let hashHelperProgram = ZkProgram({
    name: 'ecdsa-hash-helper',
    publicInput: Message,
    publicOutput: MessageHash,

    methods: {
      short: {
        privateInputs: [],
        async method(message: DynamicBytes) {
          let intermediateHash = DynamicSHA3.keccak256(message);
          let messageHash = Keccak.ethereum([
            ...Bytes.fromString(MESSAGE_PREFIX).bytes,
            ...intermediateHash.bytes,
          ]);
          return { publicOutput: messageHash };
        },
      },
      // TODO: implement version 2 / "long" method
    },
  });

  return hashHelperProgram;
}
