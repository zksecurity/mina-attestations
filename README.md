# Mina Attestations &nbsp; [![npm version](https://img.shields.io/npm/v/mina-attestations.svg?style=flat)](https://www.npmjs.com/package/mina-attestations)

This is a TypeScript library that implements _private attestations_: A cryptographic protocol that allows you to selectively disclose facts about yourself, using zero-knowledge proofs.

**🎮 Try our demo: [mina-attestations-demo.zksecurity.xyz](https://mina-attestations-demo.zksecurity.xyz)**

The library is available on npm and designed for all modern JS runtimes.

```
npm i mina-attestations
```

## What are private attestations? 🧑‍🎓

The attestation flow involves three parties: _issuer_, _user_ and _verifier_. They exchange two kinds of digital objects: _credentials_ and _presentations_.

1. an **issuer** makes a statement about you and hands you a certificate of that statement: a **credential**.

> Example: Your passport is a credential issued by a government agency. It contains information such as your name, birth date and citizenship.

<!-- - A credential derives its value from the credibility of the issuer: Third parties will trust the information on your passport, because they trust your government.
- To be usable, a credential has to carry a _digital signature_ by the issuer. (For modern passports in most countries, this is the case!) -->

2. the **verifier** is interested in some particular fact about you (that is contained in a credential).

> Example: To sign up users, a crypto exchange must check that they are not US citizens. The exchange acts as a verifier.

3. the **user** owns credentials. They can create **presentations** of a credential, that only disclose the information a verifier needs to know.

> Example: Prompted by the crypto exchange's request, you create a presentation, proving that your passport comes from a non-US country.
> The crypto exchange verifies that this is true, without learning anything else about you.

<!-- TODO: add diagram? -->

To summarize, roughly, in cryptographic terms: credentials are signed data, and presentations are zero-knowledge proofs about credentials.

_Private attestations_ refers to the entire protocol sketched above. A synonymous term from the academic literature is [anonymous credentials](https://www.sciencedirect.com/topics/computer-science/anonymous-credential).

## Features 💫

Mina Attestations helps you implement all parts of the private attestation flow.

- ✅ Supports [issuing credentials](#creating-credentials) as well as [requesting](#requesting-presentations),
  [creating](#creating-presentations) and [verifying](#verifying-presentations) presentations
- 🪪 [Import real-world credentials](#credential-kinds), like passports or emails, by wrapping them in a zk proof
- 💡 Selective disclosure logic is defined with the embedded [`Operation` DSL](#operations-dsl) that is feature-rich, yet simple enough for non-technical users to understand what data they share
- 🔒 Designed for integration in crypto wallets, to store credentials and authorize presentations by a signature
  - Integration in the [Pallad](https://pallad.co) wallet is underway
- 🧠 The cryptographic protocol is carefully designed to provide strong safety guarantees:
  - **Ownership**: Credentials are tied to their owner, a Mina public key, and become invalid when changing the owner.
  - **Unforgeability**: Presentations can only be created with access to their underlying credentials and an owner signature. So, credentials can even be stored with third parties without risking impersonation (if giving up privacy to those parties is acceptable).
  - **Privacy**: Presentations do not leak any data from the input credential or the owner, apart from the specific public statement they were designed to encode.
  - **Unlinkability**: Two different presentations of the same credential, or by the same user, cannot be linked (apart from out-of-band correlations like the user's IP address)
  - **Context-binding**: Presentations are bound to a specific context such as the origin of the requesting website, so that the verifier cannot man-in-the-middle and impersonate users at a third party.

Zero-knowledge proofs are implemented using [o1js](https://github.com/o1-labs/o1js), a general-purpose zk framework.

## Documentation

The remainder of this README contains documentation aimed at developers, starting from high-level examples and concepts and then moving to detailed API docs.

- [Code example: Defining a private attestation](#operations-dsl)
- [What credentials are supported?](#credential-kinds)
- [API](#api)

Apart from reading the docs, have a look at our full code examples:

- [examples/unique-hash.eg.ts](https://github.com/zksecurity/mina-attestations/blob/main/examples/unique-hash.eg.ts) - A good introduction, this example simulates the entire flow between issuer, user wallet and verifier within a single script, that is heavily commented to explain the individual steps.
- [examples/web-demo](https://github.com/zksecurity/mina-attestations/blob/main/examples/web-demo) - Source code for [mina-attestations-demo.zksecurity.xyz](https://mina-attestations-demo.zksecurity.xyz). It includes both frontend and backend and can be useful as a reference for integrating `mina-attestations` in a real application. Caveat: The example mixes two different entities, issuer and verifier, in a single web app.

> 🧑‍🎓 In the docs that follow, we occasionally assume familiarity with zk programming concepts. If you don't know what a circuit or a "public input" are, we recommend checking out the [o1js docs](https://docs.minaprotocol.com/zkapps/o1js) or a similar resource, to build background understanding. Nonetheless, our library should be easy to use even without that understanding.

<!-- One of the main contributions is a DSL to specify the attestations a verifier wants to make about a user. -->

<!--
Under the hood, private attestations rely on [zero-knowledge proofs](https://en.wikipedia.org/wiki/Zero-knowledge_proof).
Mina Attestations builds on top of [o1js](https://github.com/o1-labs/o1js), a general-purpose zk framework for TypeScript. -->

## Code example: Defining a private attestation <a id="operations-dsl"></a>

Let's look at how a verifier might specify their conditions on the user's credential, using `mina-attestations`:

```ts
import {
  Claim,
  Credential,
  DynamicString,
  Operation,
  PresentationSpec,
} from 'mina-attestations';
import { UInt64 } from 'o1js';

const String = DynamicString({ maxLength: 100 });

// define expected credential schema
let credential = Credential.Native({
  name: String,
  nationality: String,
  expiresAt: UInt64,
});

let spec = PresentationSpec(
  // inputs: credential and an additional "claim" (public input)
  { credential, createdAt: Claim(UInt64) },
  // logic
  ({ credential, createdAt }) => ({
    // we make two assertions:
    assert: [
      // 1. not from the United States
      Operation.not(
        Operation.equals(
          Operation.property(credential, 'nationality'),
          Operation.constant(String.from('United States'))
        )
      ),

      // 2. credential is not expired
      Operation.lessThanEq(
        createdAt,
        Operation.property(credential, 'expiresAt')
      ),
    ],
    // we expose the credential's issuer, for the verifier to check
    outputClaim: Operation.issuer(credential),
  })
);
```

There's much to unpack in this example, but the main thing we want to highlight is how custom logic for a presentation is defined, the _presentation spec_. This spec is created using a declarative API that specifies a custom zk circuit.

The first parameter to `PresentiationSpec()` specifies the inputs to the presentation circuit: `credential` and `createdAt`.

- `credential` defines what _type_ of credential we expect, including the data layout. Here, we expect a "native" credential defined with `Credential.Native()` (see [credential kinds](#credential-kinds)).
- `createdAt` is a so-called "claim", which means a _public input_ to this circuit. By contrast, the credential is a _private_ input.

Note: The input name "credential" in this example is arbitrary and picked by the developer. You could also have multiple credentials as inputs, and make a statement that combines their properties. Similarly, you can have many claims.

The second parameter to `PresentationSpec()` defines the circuit logic, as a function from the inputs, using our `Operations` DSL. `Operations` is, essentially, a radically simplified language for writing zk circuits, tailored to the use case of making statements about user data. It contains common operations like testing equality, comparisons, arithmetic, conditionals, hashing, etc.

There are two outputs, `assert` and `outputClaim`, both of which contain `Operation` nodes.

- `assert` tells us which conditions on the credential are proven to hold
- `outputClaim` specifies the _public output_: credential data the user directly exposes to the verifier. In this example, we expose the credential's `issuer` (hash of a public key), so that the verifier can check that the credential was issued by a legitimate entity.

The assertion logic should be easy to read for you: We check that the `nationality` doesn't equal `"United States"`. We also check a condition on the credential's `expiresAt` attribute. The idea is that the verifier can pass in the _current date_ as `createdAt`, and this check ensures the credential hasn't expired without leaking the exact expiry date.

> 🤓 By interacting with this code in your editor, you might appreciate that all our library interfaces are richly typed, using generic types to preserve as much information as possible. For example, the inferred type of `credential`, which is passed as an input to `PresentationSpec`, is carried into the callback. There, `Operations.property(credential, 'nationality')` is correctly inferred to be a `String`. This, in turn, ensures that a `String` is also passed to the `Operation.constant()`, because `Operations.equal()` requires its inputs to be of equal type.

Behind the scenes, the circuit created from a presentation spec contains more than the `assert` and `outputClaim` logic. It also verifies the authorization on all input credentials, and in addition verifies a signature by the credential owner. The latter ensures that nobody but the owner can present a credential.

### From spec to presentation request

In a typical flow, the code above would be called once in the verifier's application, and used to precompile the circuit for later verification. Then, for every user that wants to authenticate with a presentation, we would create a new _presentation request_ from the `spec`:

```ts
// VERIFIER
let request = PresentationRequest.https(
  spec,
  { createdAt: UInt64.from(Date.now()) },
  { action: 'my-app:authenticate' }
);
let requestJson = PresentationRequest.toJSON(request);
// now send request to user wallet
```

This highlights an important point: The target receiver of a presentation request is generic software, like a web3 wallet, that doesn't know about the specific attestation being proved. Therefore, we had to ensure that the serialized JSON request **fully specifies the circuit**.

The request also has to contain the input claims (here: `createdAt`), as there is no way for a wallet to come up with these custom values. The only inputs required on the wallet side to create a proof from this are the actual credential, and a user signature.

Another point is that the user, when approving the request, should be able to understand what data they share. To make this possible, we implemented a pretty-printer that converts presentation specs into human-readable pseudo-code:

<!-- TODO would be nice to show a screenshot of the Pallad prompt here -->
<!-- TODO make sure this is the actual output -->

```
credential.nationality ≠ "United States"
```

These points imply that the representation of a circuit has to be simple, and deserializable without concerns about malicious code execution.

Simplicity is the core advantage that `Operations` has over a general-purpose zk framework like o1js. It explains why we aren't using o1js as the circuit-writing interface directly.

The best part is that, by being easy to read and understand, presentation specs are also really easy to write for developers!

## What credentials are supported? <a id="credential-kinds"></a>

Conceptually, credentials are data authorized by a signature. When using credentials in a presentation, we have to verify that signature inside our circuit. If the signature uses Mina's native signature scheme (Schnorr over the Pallas curve), this is efficient.

However, most credentials that exist out there were not created with Mina in mind, and verifying their signatures is expensive in terms of circuit size, and usually complicated to implement.

To support both cases well, our library distinguishes two different kinds of credentials:

1. **Native credentials** are authorized by a Mina signature.
2. **Imported credentials** are authorized by a _zero-knowledge proof_.

For an imported credential, our presentation uses recursion and verifies the attached proof inside the circuit. For native credentials, we just verify the signature.

Since arbitrary logic can be encoded in a zk proof, imported credentials can cover a wide variety of existing credentials: You just need someone to implement an o1js circuit that verifies them. The only thing required from proofs to make them usable as an imported credentials is that their public output follows the structure `{ owner, data }`, where `owner` is the public key of the credential's owner.

For example, to "import" a passport as a credential, we need a circuit that proves it has a valid passport, and exposes the passport data in `data`. A user with their passport at hand can then wrap them in that proof and now has an imported credential.

There are cool examples for what we could "import" as a credential, that go beyond the traditional concept of a credentials. Everything you can prove in zk can be a credential!

For example, [zk-email](https://prove.email/) proves the DKIM signature on emails to support the statement "I received this particular email from this domain", which has very interesting applications.
By contrast to the original zk-email project, the imported credential version would simply expose the _entire_ email: Subject, from address and body text. Only when doing presentations, we care about hiding the content and making specific assertions about it.

### Why not do everything in one proof?

The process of first importing a credential, and then using it for a presentation, means that _two_ proofs have to be created by a user. Why not do both in one proof, if possible?

One reason for prefering separate steps is that the importing proof is usually very big, and takes a lot of time. On the other hand, presentation proofs are small. Also, presentations are one-off and designed to be used exactly once, so you really _want_ those proofs to be small. On the other hand, credentials are designed to be stored long-term, so separating them saves a lot of proof generation time if credentials can be reused.

Another reason is that modeling imported credentials as recursive proofs keeps our core library agnostic about the inner verification logic. That way, we avoid the burden of supporting all possible credentials within the library itself. Anyone can write their own "import" circuit, and still be compatible with the standard!

### What imported credentials are available now?

- ECDSA credential that wraps an Ethereum-style signature

```ts
import { EcdsaEthereum } from 'mina-attestations/imported';
```

- [ZkPass](https://zkpass.org) validator signature (partially available, final version is [WIP](https://github.com/zksecurity/mina-attestations/pull/108))

```ts
import { ZkPass, type ZkPassResponseItem } from 'mina-attestations/imported';
```

- [WIP](https://github.com/zksecurity/mina-attestations/tree/main/src/email): zk-email
- [WIP](https://github.com/piconbello/zk-passport-o1js-lib) (by another team): zk passport

## API

### Data types

<!-- highlight how to serialize every type -->

- [`CredentialSpec`](#credentialspec)
- [`StoredCredential`](#storedcredential)
  - `Credential`
- `PresentationRequest`
  - `PresentationSpec`
- `Presentation`

### `CredentialSpec`

A `CredentialSpec` defines the structure and verification logic for a credential. It specifies:

- The credential type (native, imported, unsigned)
- The data schema
- A "witness" type for private parameters
- A function `verify(...)` that verifies the credential inside a ZkProgram circuit
- A function `validate(...)` that verifies the credential in normal JS
- A function `issuer(...)` that derives a commitment to the "issuer" of the credential, e.g. a public key for signed credentials
- A function `matchesSpec(...)` that decides whether a stored credential's witness matches the spec

The serialization and deserialization of a `CredentialSpec` is handled through methods in the `Credential` namespace using:

- `Credential.specToJSON(spec: CredentialSpec): CredentialSpecJSON`
- `Credential.specFromJSON(json: CredentialSpecJSON): CredentialSpec<any, any>`.

#### Native Credential example

```typescript
import { Field, Bytes } from 'o1js';
import { Credential } from 'mina-attestations';

// Define schema with a fixed-size Bytes type
const Bytes32 = Bytes(32);
const InputData = {
  age: Field,
  name: Bytes32,
};

// Create native credential spec
const SignedData = Credential.Native(InputData);

// Issue a credential using the spec
const data = {
  age: Field(25),
  name: Bytes32.fromString('Alice'),
};
const signedCredential = Credential.sign(issuerKey, { owner, data });

// Validate the credential
await Credential.validate(signedCredential);
```

#### Imported Credential example

```typescript
import { Field, UInt64 } from 'o1js';
import { Credential, DynamicString } from 'mina-attestations';

const Nationality = DynamicString({ maxLength: 50 });

// Create imported credential spec
const PassportCredential = await Credential.Imported.fromMethod(
  {
    name: 'passport',
    publicInput: { issuer: Field },
    privateInput: {
      nationality: Nationality,
      expiresAt: UInt64,
    },
    data: {
      nationality: Nationality,
      expiresAt: UInt64,
    },
  },
  async ({ privateInput }) => {
    return privateInput;
  }
);

// Create a credential with proof
const passport = await PassportCredential.create({
  owner,
  publicInput: { issuer: 1001 },
  privateInput: {
    expiresAt: UInt64.from(Date.UTC(2027, 1, 1)),
    nationality: 'Austria',
  },
});

// Validate the credential
await Credential.validate(passport);
```

#### Unsigned Credential example

```typescript
import { Field } from 'o1js';
import { Credential } from 'mina-attestations';

// Define simple schema
const InputData = { value: Field };

// Create unsigned credential spec
const UnsignedSpec = Credential.Unsigned(InputData);

// Create an unsigned credential
const unsignedCredential = Credential.unsigned({
  value: Field(123),
});
```

### `StoredCredential`

A `StoredCredential` represents a credential in its stored form, containing all necessary data for verification and usage in presentations. It specifies:

- A version identifier for future compatibility
- A witness that provides verification data that proves the credential's authenticity
  - For native credentials it contains the issuer's public key and signature
  - For imported credentials it contains a verification key and a proof
  - For unsigned credentials it is undefined, since unsigned credentials don't prove their authenticity
- An optional metadata associated with the credential
  - Can store any JSON-serializable data
- A credential which is the core credential data containing:
  - The owner's public key
  - The data that contains the actual credential attributes

The serialization and deserialization of a `StoredCredential` is handled through methods in the `Credential` namespace using `Credential.toJSON(...)` and `Credential.fromJSON(...)`.

### `Credential`

The `Credential` namespace provides the main interface for working with credentials. It has the following static properties:

- `Native<DataType extends NestedProvable>(
  dataType: DataType
): CredentialSpec<NativeWitness, InferNestedProvable<DataType>>`: Factory for creating native credential specifications
- `Imported`: Namespace for creating credential specifications that use zero-knowledge proofs for verification.
- `Unsigned<DataType extends NestedProvable>(
  data: DataType
): CredentialSpec<undefined, InferNestedProvable<DataType>>`: Factory for creating unsigned credential specifications

It also specifies the following methods:

- `sign<Data>(issuerPrivateKey: PrivateKey, credentialInput: Credential<Data> | string, metadata?: JSONValue): Native<Data>`

  - Creates a new native credential signed by the issuer
  - Parameters:
    - `issuerPrivateKey`: The private key of the issuer
    - `credentialInput`: Either a credential object of its JSON string representation
    - `metadata`: Optional metadata to attach to the credential
  - Returns:
    - A new native credential

- `unsigned<Data>(data: Data, metadata?: JSONValue): Unsigned<Data>`
  - Creates a new unsigned, dummy credential with no owner and no signature
  - Parameters:
    - `data`: The credential data
    - `metadata`: Optional metadata to attach to the credential
  - Returns:
    - A new unsigned credential

> ⚠️ Unsigned credentials use a dummy owner key and should only be used for testing!

- `toJSON(credential: StoredCredential): string`

  - Serializes a credential to JSON format
  - Parameters:
    - `credential`: The credential to serialize
  - Returns:
    - JSON string representation

- `fromJSON(json: string): Promise<StoredCredential>`

  - Deserializes a credential from JSON format
  - Parameters:
    - `json`: JSON string representing a credential
  - Returns:
    - Promise resolving to the deserialized credential

- `validate(credential: StoredCredential): Promise<void>`

  - Validates a credential's authenticity
  - Parameters:
    - `credential`: The credential to validate
  - Returns:
    - Promise that resolves if validation succeeds, rejects if validation fails

- `dataToJSON<Data>(credential: Credential<Data>): string`

  - Serialize the data input to a `signCredential()` call.
    The resulting string is accepted as input to `Credential.sign()`
  - Parameters:
    - `credential`: Credential data to serialize
  - Returns:
    - JSON string representation of credential data
  - Example:

    ```typescript
    let credentialData = { owner: publicKey, data: { name: 'Alice' } };
    let credentialDataJson = Credential.dataToJSON(credentialData);

    let credential = Credential.sign(privateKey, credentialDataJson);
    ```

#### Credential example

```typescript
import { Field, PrivateKey } from 'o1js';
import { Credential } from 'mina-attestations';

// Create a native credential spec
const spec = Credential.Native({ age: Field });

// Issue a credential
const issuerKey = PrivateKey.random();
const owner = PrivateKey.random().toPublicKey();
const data = { age: Field(25) };

const credential = Credential.sign(
  issuerKey,
  { owner, data },
  {
    issuedAt: Date.now(), // optional metadata
  }
);

// Serialize
const json = Credential.toJSON(credential);

// Deserialize and validate
const recovered = await Credential.fromJSON(json);
await Credential.validate(recovered);
```

#### Credential types

```typescript
// Native credential type
type Native<Data> = StoredCredential<
  Data,
  {
    type: 'native';
    issuer: PublicKey;
    issuerSignature: Signature;
  }
>;

// Imported credential type
type Imported<Data, Input> = StoredCredential<
  Data,
  {
    type: 'imported';
    vk: VerificationKey;
    proof: DynamicProof<Input, Credential>;
  }
>;

// Unsigned credential type
type Unsigned<Data> = StoredCredential<Data, undefined>;
```

### Creating credentials

The `Credentail` namespace provides several methods to help create different types of credentials:

#### Native Credential

`Credential.sign<Data>(issuerPrivateKey: PrivateKey, credentialInput: Credential<Data> | string, metadata?: JSONValue): Native<Data>`

- Creates a new native credential signed by the issuer
- Parameters:
  - `issuerPrivateKey`: The private key of the issuer
  - `credentialInput`: Either a credential object of its JSON string representation
  - `metadata`: Optional metadata to attach to the credential
- Returns:
  - A new native credential

Example:

```typescript
let data = { age: Field(18), name: Bytes32.fromString('Alice') };
let signedData = Credential.sign(issuerKey, { owner, data });
```

#### Unsigned Credential

`Credential.unsigned<Data>(data: Data, metadata?: JSONValue): Unsigned<Data>`

- Creates a new unsigned, dummy credential with no owner and no signature
- Parameters:
  - `data`: The credential data
  - `metadata`: Optional metadata to attach to the credential
- Returns:
  - A new unsigned credential

Example:

```typescript
const unsignedCredential = Credential.unsigned({
  value: Field(123),
});
```

#### Imported Credential

To import credentials we have to use the `Credential.Imported` namespace and follow the following pattern:

1. First create the specification using fromMethod or fromProgram
2. Get back an object that contains both the spec and helper functions
3. Use the create function that came with that object to create actual credentials

Methods to create specifications:

`Credential.Imported.fromProgram(program)`

Creates an imported credential specification from an existing o1js ZkProgram.

```typescript
async function fromProgram
  DataType extends ProvableType,
  InputType extends ProvableType,
  Data extends InferProvable<DataType>,
  Input extends InferProvable<InputType>,
  AllInputs extends any[]
>(program: {
  publicInputType: InputType;            // Type of public inputs
  publicOutputType: ProvableType<Credential<Data>>; // Output must be a credential
  analyzeMethods(): Promise<Record<string, any>>;   // For analysis
  maxProofsVerified(): Promise<0 | 1 | 2>;         // Max proofs to verify
  compile(options?: {                    // Compilation
    cache?: Cache;
    forceRecompile?: boolean;
    proofsEnabled?: boolean;
  }): Promise<{ verificationKey: VerificationKey }>;

  run(...inputs: AllInputs): Promise<{   // Program execution
    proof: Proof<Input, Credential<Data>>;
    auxiliaryOutput: undefined;
  }>;
}): Promise<{
  spec: CredentialSpec;          // The credential specification
  program: Program;             // The original program
  compile(): Promise<VerificationKey>;  // Compile the program
  create(...inputs: AllInputs): Promise<Imported<Data, Input>>;  // Create credential
  fromProof(proof: Proof<Input, Credential<Data>>, vk: VerificationKey): Promise<Imported<Data, Input>>;  // Create from existing proof
  dummy(credential: Credential<From<DataType>>): Promise<Imported<Data, Input>>;  // Create dummy credential
}>;
```

Example:

```typescript
import { Field, Bytes, PublicKey, ZkProgram, Struct, Proof } from 'o1js';
import { Credential } from 'mina-attestations';
import { owner } from './test-utils.ts'; // dummy owner used for testing

const Bytes32 = Bytes(32);
const InputData = { age: Field, name: Bytes32 };

// Create a program that outputs a credential with InputData
const program = ZkProgram({
  name: 'importedCredential',
  publicInput: {
    // Matches the Spec claims
    inputOwner: PublicKey,
    data: InputData,
  },
  publicOutput: Struct({
    // Matches Operation.record output
    owner: PublicKey,
    data: InputData,
  }),
  methods: {
    create: {
      privateInputs: [], // No private inputs needed
      method(publicInput: { inputOwner: PublicKey; data: typeof InputData }) {
        // Simply pass through the input as credential
        return {
          publicOutput: {
            owner: publicInput.inputOwner,
            data: publicInput.data,
          },
        };
      },
    },
  },
});

// Create imported credential specification from program
const Imported = await Credential.Imported.fromProgram(program);

// Create verification key
const vk = await Imported.compile();

// Create credential data
let data = {
  age: Field(18),
  name: Bytes32.fromString('Alice'),
};

// First create a proof using the program directly
const { proof } = await program.create({
  inputOwner: owner,
  data: data,
});

// Create a credential using fromProof
let provedData = await Imported.fromProof(proof, vk);

// Create a credential using create
let provedData2 = await Imported.create({
  inputOwner: owner, // Public inputs match program's publicInput type
  data: data,
});
```

`Credential.Imported.fromMethod(config, method)`

Creates an imported credential spec from a configuration object and method.

```typescript
async function fromMethod<
  Config extends {
    name: string;
    publicInput?: NestedProvable; // Optional public input type
    privateInput?: NestedProvable; // Optional private input type
    data: NestedProvable; // Credential data type
  }
>(
  spec: Config,
  method: (inputs: {
    publicInput: PublicInput<Config>;
    privateInput: PrivateInput<Config>;
    owner: PublicKey;
  }) => Promise<Data<Config>>
): Promise<{
  spec: CredentialSpec;
  create(inputs: {
    publicInput: From<PublicInputType>;
    privateInput: From<PrivateInputType>;
    owner: PublicKey;
  }): Promise<Imported<Data, Input>>;
}>;
```

Example:

```typescript
import { Field, UInt64 } from 'o1js';
import { Credential, DynamicString } from 'mina-attestations';

const Nationality = DynamicString({ maxLength: 50 });

let PassportCredential_ = await Credential.Imported.fromMethod(
  {
    name: 'passport',
    publicInput: { issuer: Field },
    privateInput: { nationality: Nationality, expiresAt: UInt64 },
    data: { nationality: Nationality, expiresAt: UInt64 },
  },
  async ({ privateInput }) => {
    return privateInput;
  }
);
let PassportCredential = Object.assign(PassportCredential_, { Nationality });
let vk = await PassportCredential.compile();

// user "imports" their passport into a credential, by creating a PassportCredential proof
let cred = await PassportCredential.create({
  owner,
  publicInput: { issuer: 1001 },
  privateInput: {
    expiresAt: UInt64.from(Date.UTC(2027, 1, 1)),
    nationality: 'Austria',
  },
});
```

`Credential.Imported.create(data, witness)`

Creates an imported credential specification by directly specifying the data type and witness specification

```typescript
function create<DataType extends NestedProvable, InputType extends ProvableType>({
  data: DataType;                // Schema for the credential data
  witness: ImportedWitnessSpec;  // Specification for the witness/proof
}): CredentialSpec<ImportedWitness<Input>, Data>
```

Example:

```typescript
Credential.Imported.create({
  data: Field,
  witness: ProofSpec,
});
```

> This is a lower-level method compared to `fromMethod` or `fromProgram`. It's used internally by those methods but can also be used directly when you need full control over the witness specification.

### Defining presentation logic

<!-- Both `assert` and `outputClaim` are optional, so the following would define a circuit without any custom logic:

```ts

````

-->

### Requesting presentations

### Creating presentations

### Verifying presentations

### Defining new imported credentials

## Bonus: `mina-attestations/dynamic`

<!-- TODO Rename the lib to `o1js-dynamic` and publish as its own npm package, to make it look less mina-attestations specific and more likely to be adopted everywhere -->

Under the sub-import `mina-attestations/dynamic`, we export an entire library of dynamic data types and hashes with o1js.

Features:

- `DynamicSHA2` for hashing dynamic-length inputs with SHA2-256, -224, -384 or -512
- `DynamicSHA3` for hashing dynamic-length inputs with Keccak256
- `DynamicString` and `DynamicBytes` for representing strings and bytes, with many useful methods for manipulating strings in a circuit
- `DynamicArray`, a generalization of the above types to an arbitrary element type
- `StaticArray`, which provides an API consistent with `DynamicArray` but for fixed-length arrays
- `DynamicRecord`, a wrapper for objects that you don't necessarily know the exact layout of, but can be hashed and accessed properties of inside a circuit
- `hashDynamic()`, for Poseidon-hashing pretty much any input (including plain strings, records, o1js types etc) in a way which is compatible to in-circuit hashing of padded data types like `DynamicRecord` and `DynamicArray`
- `toDecimalString()`, a gadget to compute the variable-length decimal string from a `Field`

The sub-library is intended to help with importing **real-world credentials** into the Mina ecosystem: For example, to "import" your passport, you have to verify the passport authority's signature on your passport data. The signature relies one of several hashing and signature schemes such as ECDSA, RSA and SHA2-256, SHA2-384, SHA2-512. Also, the signature will be over a dynamic-length string.

Example of SHA-512-hashing a dynamic-length string:

```ts
import { Bytes, ZkProgram } from 'o1js';
import { DynamicSHA2, DynamicString } from 'mina-attestations/dynamic';

// allow strings up to length 100 as input
const String = DynamicString({ maxLength: 100 });

let sha512Program = ZkProgram({
  name: 'sha512',
  publicOutput: Bytes(64); // 64 bytes == 512 bits

  methods: {
    run: {
      privateInputs: [String],
      async method(string: DynamicString) {
        let publicOutput = DynamicSHA2.hash(512, string);
        return { publicOutput };
      },
    },
  },
});

await sha512Program.compile();

let result = await sha512Program.run(String.from('Hello, world!'));
let provenHash: Bytes = result.proof.publicOutput;

console.log(provenHash.toHex());
```

<!-- ## Further resources and background

TODO: references to various md docs and papers and examples -->

## Acknowledgement

We thank [Mina Foundation](https://www.minafoundation.com/) for funding this work with a grant, and for providing us with valuable feedback and direction throughout. Link to the original grant proposal: https://github.com/MinaFoundation/Core-Grants/issues/35#issuecomment-2318685738

We thank o1Labs for creating and open-sourcing [o1js](https://github.com/o1-labs/o1js). Some of our code, such as the SHA2, Keccak and RSA gadgets, were seeded by copying code from the o1js repo and modifying it to fit our needs.

We thank the [zk-email project](https://github.com/zkemail) for creating and open-sourcing zk-email. We took great inspiration for our own (unfinished) zk-email implementation. Our TS code that prepares emails for in-circuit verification was seeded by copying over files from [zk-email-verify](https://github.com/zkemail/zk-email-verify); some parts of it still exist in our code almost unchanged.

## License

[Apache-2.0](LICENSE)

Copyright 2024-2025 zkSecurity

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
