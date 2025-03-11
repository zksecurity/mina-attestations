# RSA o1js

This folder contains types, provable methods and zkprograms to verify RSA65537 signature in o1js.

"RSA o1js" can be seen as its own, self-contained library which is generally useful, beyond attestations. It can be imported from `mina-attestations/rsa`.

The `rsa.eg.ts` file provides an example of using `rsaVerify65537` in `ZkProgram`, while `rsa.test.ts` includes tests for generating arguments and verifying `rsaVerify65537` outside the circuit.
## Core Components

### `Bigint2048`
- A specialized class for handling 2048-bit integers used in RSA cryptography
- Uses 18 field elements with 116-bit limbs for efficient circuit representation
- Provides modular arithmetic operations (multiplication and squaring) necessary for RSA
- Includes conversion methods between native bigints and the circuit-friendly representation

### `rsaVerify65537`
- Implements RSA signature verification for the common public exponent e=65537
- Follows the RSASSA-PKCS1-v1.5 signature scheme standard
- Verifies signatures by computing signature^(2^16+1) mod modulus and comparing to padded message


### `rsaSign`
- Generates RSA signatures according to RSASSA-PKCS1-v1.5 scheme
- Takes a message hash (expected to be pre-computed) and private key components
- Not designed to be provable, intended for off-chain signature generation

## Utils
 Provides cryptographic utilities including key generation, primality testing, and byte conversion functions necessary for RSA operations
  - `power`: Performs modular exponentiation (a^n mod p) efficiently using the square-and-multiply algorithm
  - `generateRsaKeys65537`: Creates a random set of 2048-bit RSA keys with the fixed public exponent 65537
  - `randomPrime`: Generates cryptographically secure random prime numbers of specified bit length using Miller-Rabin primality testing
  - `bytesToBigint`: Converts a byte array to a bigint using little-endian byte order
  - `bigintToBytes`: Converts a bigint to a byte array using little-endian byte order
  - `bytesToBigintBE`: Converts a byte array to a bigint using big-endian byte order
  - `bigintToBytesBE`: Converts a bigint to a byte array using big-endian byte order

  Example to verify rsa65537 signature using `mina-attestations/rsa`
  ```ts
import { Bytes, ZkProgram } from 'o1js';
import { SHA2 } from 'mina-attestations/dynamic';
import { rsaVerify65537, rsaSign, Bigint2048, generateRsaKeys65537 } from 'mina-attestations/rsa';


let keys = generateRsaKeys65537();

let message = SHA2.hash(256, 'a test message');
let signature = rsaSign(message, keys);

const Message = Bytes(32);

let rsaProgram = ZkProgram({
  name: 'rsa',
  publicInput: Message,

  methods: {
    run: {
      privateInputs: [Bigint2048, Bigint2048],

      async method(message: Bytes, signature: Bigint2048, modulus: Bigint2048) {
        rsaVerify65537(message, signature, modulus);
      },
    },
  },
});

console.log((await rsaProgram.analyzeMethods()).run.summary());

await rsaProgram.compile();

// Run the program
await rsaProgram.run(
  message,
  Bigint2048.from(signature),
  Bigint2048.from(keys.n)
);


  ```