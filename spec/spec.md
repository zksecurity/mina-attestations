# Technical Specification for Mina Credentials

This document is a low-level technical specification for the Mina Credentials system.
It is intended as document for the accompanying codebase and implementators.
It does not include security proofs or motivations for the design choices.

# Metadata

Metadata SHOULD NOT be constrained during the creation of a credential.
Metadata MUST NOT be used to determine the validity of a credential or its issuer.
Metadata MUST only be used to present information about the credential in a human-readable way
inside wallets and other applications for easy identification and selection.
Metadata MUST NOT be used to make trust decisions.
Metadata MUST NOT be presented to the verifier during the presentation of a credential.

# Formats

## Mina Credential

A credential is a set of attributes and an owner:

```typescript
type Any = ... // any o1js type

type Data = {
  [key: string]: Any;
};

type Credential = {
  owner: PublicKey; // the owners' public key
  data: Data; // struct of hidden attributes (e.g. age, name, SSN)
};
```

Is is stored along with metadata and the version of the credential:

```typescript
type Witness =
  | { type: 'native'; issuer: PublicKey; issuerSignature: Signature }
  | {
      type: 'imported';
      vk: VerificationKey;
      proof: DynamicProof<Any, Credential>; // o1js proof with any type for public input
    };
```

```typescript
type StoredCredential = {
  version: 'v0';
  witness: Witness;
  metadata: Metadata;
  credential: Credential;
};
```

Wallets MUST import/export credentials in this format, but MAY store them in any format internally.
Wallets MUST validate the credential before importing it, we describe the validation procedure in this document.
Note: validating a credential does not require access to the owner's private key.

## Mina Credential Presentation

The presentation proof is encoded as follows:

```typescript
type Presentation = {
  version: 'v0';
  proof: Proof;
  claims: Claims; // application specific public inputs
  outputClaim: Claim; // application specific public output
  serverNonce: Field; // included so that servers can potentially retrieve the presentation request belonging to this presentation
  clientNonce: Field;
};
```

## Mina Credential Metadata

Metadata is a general key-value map. We standardize a few fields for interoperability across wallets:
so that e.g. wallet can display an issuer name and icon for any compatible credential.
Issuers may add their own fields as needed.

Standardized fields are:

- `name`: The name of the credential: utf-8 encoded string.
- `issuerName`: The name of the issuer: utf-8 encoded string.
- `description`: A human-readable description of the credential: utf-8 encoded string.
- `icon`: A byte array representing an icon for the credential.

Any fields (inlcuding the standardized ones) MAY be omitted,
wallets MUST handle the absence of any field gracefully, e.g. with a default icon.
Wallets MUST NOT make trust decisions based on metadata, in particular,
wallets MUST NOT verify the issuer based on the `issuerName` field.
Wallets MAY ignore ANY metadata field.

```typescript
type Metadata = {
  name: String,
  issuerName: String,
  description: String,
  icon: Uint8Array, // svg, jpg, png, webp, etc.
  ...
};
```

<!--
TODO do we need a metaHash in `Credential`?

The `metaHash` field of the credential is the hash of the metadata.
The `metaHash` field MUST be computed using `Keccak256` over the metadata.

```typescript
metaHash = Keccak256.hash(metadata);
``` -->

# Protocols

## Presentations

- The presentation proofs MUST NOT be reused.
- The presentation proofs MUST be generated for each presentation.
- The presentation MUST NOT contain the "context" field, which MUST be recomputed by the verifier.
- The presentation MUST NOT include the `metadata` of the credential.

### Public Inputs

The public inputs/outputs for the presentations circuits (native and imported) are:

```typescript
type PublicInput = {
  context: Field; // context: specified later
  claims: Claims; // application specific public inputs
};

type PublicOutput = Claim; // application specific public output
```

### Circuit: Present Native Credential

A standardized circuit for presenting native credentials.

The circuit verifies two signatures: one from the issuer and one from the owner.

```typescript
// the private inputs for the circuit
type PrivateInput = {
  credential: Credential;
  issuer: PublicKey;
  issuerSignature: Signature;
  ownerSignature: Signature;
};

// hash the credential
let credHash = Poseidon.hashPacked(Credential, credential);

// verify the credential issuer signature
issuerSignature.verify(issuer, credHash);

// convert issuerPK to opaque field element
let issuer = Poseidon.hashWithPrefix(
  'mina-cred:v0:native', // sep. the domain of "native" and "imported" issuers
  issuerPk
);

// verify the credential owner signature
ownerSignature.verify(credential.owner, [context, issuer, credHash]);

// verify application specific constraints using the standard API
let outputClaim = applicationConstraints(
  credential, // hidden attributes/owner
  issuer, // potentially hidden issuer
  claims // application specific public input
);
```

### Circuit: Present Imported Credential

A standardized circuit for presenting imported credentials.

The circuit verifies a proof "from" the issuing authority and a signature from the owner.

```typescript
// the private inputs for the circuit
type PrivateInput = {
  credVk: VerificationKey;
  credInput: CredentialInput; // public input specific to the imported credential
  credProof: Proof;
  credential: Credential;
  ownerSignature: Signature;
};

// hash the credential
let credHash = Poseidon.hashPacked(Credential, credential);

// verify the credential proof
credProof.publicInput.assertEquals(credInput);
credProof.publicOutput.assertEquals(credential);
credProof.verify(credVK);

// the issuer is identified by the imported relation and public input
let credIdent = Poseidon.hashPacked(CredentialInput, credInput);
let issuer = Poseidon.hashWithPrefix(
  'mina-cred:v0:imported', // sep. the domain of "native" and "imported" issuers
  [vk.hash, credIdent] // identifies the issuing authority / validation logic
);

// verify the credential owner signature
ownerSignature.verify(credential.owner, [context, issuer, credHash]);

// verify application specific constraints using the standard API
let outputClaim = applicationConstraints(
  credential, // hidden attributes/owner
  issuer, // potentially hidden issuer
  claims // application specific public input
);
```

# Context Binding

The verifier computes the context (out-of-circuit) as:

```typescript
context = Poseidon.hashWithPrefix(
  'mina-cred:v0:context', // for versioning
  [
    type, // seperates different types of verifiers
    presentationCircuitVK.hash, // binds the presentation to the relation
    nonce, // a random nonce to prevent replay attacks
    verifierIdentity, // verifiers identifier
    action, // the "action" being performed (e.g. login, transaction hash etc.)
    claims, // the public input (the set of "claims" being presented)
  ]
);
```

The nonce MUST be generated as follows:

```typescript
let nonce = Poseidon.hashWithPrefix('mina-cred:v0:nonce', [
  serverNonce,
  clientNonce,
]);
```

- The `clientNonce` MUST be a uniformly random field element generated by the client.
- The `clientNonce` MUST never be reused.
- The `serverNonce` MAY be zero in applications where storing the set of expended nonces indefinitely is not a concern.

Usual applications of `serverNonce` is to seperate the nonce space into "epochs" to prevent storage of all nonces indefinitely:
for instance, a timestamp may be used and validity requires the timestamp to be recent.
Allowing the server to only store nonces for a limited time.

## zkApp

```typescript
let type = Keccak256.hash("zk-app")

let verifierIdentity = {
  publicKey, // mina address of the zkApp
  tokenId, // token id of the zkApp
  networkId, // network id of the zkApp
}

let action = Poseidon.hash([METHOD_ID, ARG1, ARG2, ...])
```

The ZK app MUST check the validity of the presentation proof and the claims.

## Web Application

[Uniform Resource Identifier](https://datatracker.ietf.org/doc/html/rfc3986)

```typescript
let type = Keccak256.hash('https');

let verifierIdentity = Keccak256.hash('example.com');

let action = Keccak256.hash(HTTP_REQUEST);
```

The scheme MUST be `https`.

Keccak is used to improve efficiency when the HTTP request is long: such as uploading a file.
