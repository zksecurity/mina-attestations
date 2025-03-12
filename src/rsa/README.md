# o1js RSA

This folder contains types, provable methods and zkprograms to verify RSA65537 signature in o1js.

o1js RSA can be seen as its own, self-contained library which is generally useful, beyond attestations. It can be imported from `mina-attestations/rsa`.

The `rsa.eg.ts` file provides an example of using `rsaVerify65537()` in `ZkProgram`.

Core Components:

- **`Bigint2048`**
  - Provable type for 2048-bit integers used in RSA
  - Uses 18 field elements with 116-bit limbs for efficient circuit representation
  - Has modular multiplication and squaring necessary for RSA, plus conversion to bigint
- **`rsaVerify65537()`**
  - Implements RSA signature verification for the common public exponent e=65537
  - Follows the RSASSA-PKCS1-v1.5 signature scheme standard
- **`rsaSign()`**
  - Generates RSA signatures according to RSASSA-PKCS1-v1.5 scheme
  - Not designed to be provable, intended for off-chain signature generation

Utils:

- `generateRsaKeys65537()`: Creates a random set of 2048-bit RSA keys with the fixed public exponent 65537
- `randomPrime()`: Generates cryptographically secure random prime numbers of specified bit length, using Miller-Rabin primality testing
- `millerRabinTest()`: Implements the Miller-Rabin probabilistic primality test
- `power()`: Performs modular exponentiation $a^n mod p$ using the square-and-multiply algorithm

Example to prove verification of an RSA signature using `mina-attestations/rsa`:

```ts
import { Bytes, ZkProgram } from 'o1js';
import { SHA2 } from 'mina-attestations/dynamic';
import {
  rsaVerify65537,
  rsaSign,
  Bigint2048,
  generateRsaKeys65537,
} from 'mina-attestations/rsa';

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
