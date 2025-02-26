# The Design of Mina Attestations

This document is a high-level overview of the Mina Attestations system,
its relation to other systems, its (informal) design goals and rationale for the design choices made in the system.

> See [the RFC by Mina Foundation](https://github.com/MinaFoundation/Core-Grants/blob/1fb5d2335b1a2b77249e41b9d593edcb8a8bbce1/RFCs/rfc-0009-wallet-attestation-api.md) for additional background and motivation.

The goal of this project is to design a system sufficiently flexible to encompass any "anonymous credential"-style application,
while unifying the user interface, API and design with the aim of providing a clear specification with minimal footgun potential.

This is achieved by using the recursive proofs of Mina extensively:
seperating the "creation" of the credential from the "presentation" of the credential:
besides unifying the presentation proof, it also allows doing most of the expensive operations (e.g. verifying an RSA signature using SHA256 and parsing a JSON object) once during the creation of the credential.

At the highest possible level of abstraction, credentials
are a set of "attributes" (e.g. name, age, SSN) attested to by a "issuer".
The issuer is an opaque entity (a hash) and may identify e.g. the root of a Merkle tree,
the root authorities of a PKI, the hash of Google's OAuth public key, etc.
By exploiting the recursive proofs of Mina, this diverse set of issuers / applications
can be brought into a standard form: a SNARK on a hash of the attributes.
All these credentials can also be stored/verified/used in the same way.
This provides a plug-and-play system:
allowing developers to create new credential types and application logics seperately, combining them in a safe, modular way.

# Related Works & Systems

- [zkLogin](https://docs.sui.io/concepts/cryptography/zklogin)
- [zkPassport](https://zkpassport.id/)
- [World ID and Semaphore](https://worldcoin.org/blog/worldcoin/intro-zero-knowledge-proofs-semaphore-application-world-id)

The goal of Mina credentials is broader than these systems and must enable
the implementation of these systems within the Mina ecosystem.

# Design Rationale

The cryptography team considered two options for the presentation proof.

1. Credentials are "bearer tokens": simply knowing the credential is sufficient to present it.
2. Credentials are attributes/capabilities associated to public keys.

To explain our choice, let us first explore the two options in more detail.

## Option 1: "Bearer Tokens"

In this scenario, the simpler of the two, knowing the credential is equivalent to owning it.
Let us make that more concrete. For instance, the credential might simply be a signature over a set of attributes:

```javascript
cred = {
  'attributes': {
    'name': 'Alice',
    'age': 25,
    'ssn': '123-45-6789'
  },
  'signature': '---signature---'
  'issuer': '---issuer public key---'
}
```

Knowing this signed object is equivalent to "being" Alice.
To "present" the credential, to e.g. show that Alice is over 18, Alice creates a proof of the following relation:

```javascript
// verify the issuer signature
cred.signature.verify(cred.issuer, cred.attributes);

// check the issuer
assert(cred.issuer == issuer);

// verify the claim
assert(cred.attributes['age'] >= 18);
```

Using the context of the presentation as a public input to the proof:
the context is a domain-specific hash of the context in which the credential is presented,
incorporating the entity to which the credential is presented, a nonce to avoid replay attacks and additional information as needed.
We describe this in more detail in the formal specification.

## Option 2: "Associated Attributes"

In this scenario, the credential is associates a set of attributes with a public key.
Knowning the corresponding signing key allows one to present the credential.
To make this more concrete, the credential might look like this:

```javascript
cred = {
  'owner': '---owner public key---',
  'attributes': {
    'name': 'Alice',
    'age': 25,
    'ssn': '123-45-6789'
  },
  'signature': '---signature---'
  'issuer': '---issuer---'
}
```

To "present" the credential, Alice creates a proof of the following relation:

```javascript
// verify the issuer signature
cred.signature.verify(cred.issuer, cred.owner, cred.attributes);

// verify the owner signature
ownerSignature.verify(cred.owner, [cred.attributes, cred.issuer, context]);

// check the issuer
assert(cred.issuer == issuer);

// verify the claim
assert(cred.attributes['age'] >= 18);
```

Again, using the context as a public input to the proof: but now the context is also signed by the owner
and the signature is verified in-circuit.

## Justification

We deemed that the additional complexity of the second option,
an in-circuit verification of a native signature,
is outweighed by the following benefits:

- Allow use of existing infrastructure for key management.
  Including hardware enclaves and the ability to authortize presentations efficiently using MPC:
  authortization requires the parties to threshold sign using Schnorr.

- Outsourcing the computation of the proofs is possible at the cost of privacy:
  the user must reveal the credential and the context to the prover, but the prover cannot impersonate the user or change the intended action.
  This is useful in scenarios where the prover is a resource-constrained device,
  or in applications such as zkLogin, where for practicality reasons, the proving is outsourced to a third party.
  We want to allow the Mina ecosystem this option should it be relevant to particular applications.

- A compromise of the credential object itself does not allow impersonation.

- Easy integration with the existing Nullifier system within Mina: every credential comes with a public key
  and nullifiers can be computed / exposed against this public key to allow linkability when desired.

- From a theorectical/robustness perspective, a small benefit is that we can assume weaker properties of the proof system:
  the first scheme requires [(weak) simulation extractability](https://eprint.iacr.org/2020/1306.pdf).

<!-- TODO We obtain a design in which the SNARK serves only to hide the -->

<!-- TODO: previous RFC text goes below, commented for now because unfinished -->

<!-- # Attestation Protocol

## Assumptions

We assume that the Kimchi (the underlying proof) is a Zero-Knowledge Argument of Knowledge:

- **Zero-Knowledge:** Kimchi is (perfect) Zero-Knowledge.
- **Proof-of-Knowledge:** Kimchi is extractable (in the random oracle model).

We do not assume simulation extractability ("non-malleability") of Kimchi,
although Kimchi is likely to satisfy this stronger property. \
Our construction does not assume non-malleability of the zkSNARK and
hence security is retained even if the zkSNARK was replaced with a malleable proof system (such as Groth16).

## Formal Security Goals

We prove that the construction detailed in this RFC satisfy the following security properties:

> **Privacy: Simulation.**
>
> **Informally:** The adversary should not be able to
>
> Formally, we define this as the ability to simulate a presentation
> A

> **Unforgeability: Simulation Extractability.**
>
> **Informally:** The adversary should not be able to present a credential to the verifier without having a valid credential.
>
> Formally, we define this as the ability to extract a witness (e.g. a valid signature by the issuer) from a presentation:
>
> Adv()

This condition holds even when _the adversary has access to an oracle_ that can generate valid presentation proofs for arbitrary statements.

This serves to formalize that the adversary is unable to create valid presentations even if it has access to other valid presentations,
or is able to execute a "man-in-the-middle" attack on the credential presentation:
forwarding a clients proof as if it was its own.

## Further Security Considerations

The following consideration is formally covered by unforgeability, but should be considered by applications interacting with this RFC:

**Context Binding:** It is rarely intresting to present a credential without binding the presentation to some additional data.\
For instance, the presentation of a credential may allow spending from an account,
in such a scenario the presentation should be bound to the transaction: the recipient, the amount, etc. to prevent the transaction from being mauled.
This specification details how to bind _arbitrary data_ to the presentation,
it is beyond the scope of this specification to detail how such data should be derived:
applications are expected to ensure that context bound to the presentation is sufficient to meet application-specific security requirements.

**Hardware Wallets:** Every credential has an `owner` field, a Mina public key, and the credential can only be used by signing with the corresponding private key. \
This enables hardware-wallet support for credentials:
the hardware wallet the context in which the credential is used, but does not need to compute the costly proof.
In the case of a compromised prover (browser), the attacker learns the attributes of the credential,
but is unable to use the credential to sign transactions or otherwise impersonate the credential owner.

**Compromised Credentials:** We use the flexibility afforded by the Kimchi proof
system to reduce the practical impact of a compromised credential.

## Protocols

### Credential Types

At a high level, a credential is a collection of _attributes_ along a proof and corresponding verification procedure:
checking the validity of the credential.

#### Native Credentials

A native credential is simply a native Mina signature on the set of attributes.
This type of credential is supported to allow Mina-native application to have very efficient credentials.

#### Imported Credentials

An imported credential is a Kimchi proof taking the set of attributes as public input.
This type of credential is supported to accomodate any possible credential
and the ability to integrate existing credential systems (such as ePassport) into the Mina ecosystem
in a modular way.

- ECDSA signatures over foreign fields on JSON document (e.g. JSON Web Tokens),
- RSA signatures.
- Merkle tree inclusion/exclusion proofs. -->
