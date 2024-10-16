# The Design of Mina Credentials

This document is a high-level overview of the Mina Credentials system,
its relation to other systems, its (informal) design goals and rationale for the design choices made in the system.
The goal of this project is to design a system sufficiently flexible to encompass any "anonymous credential"-style application,
while unifying the user interface, API and design with the aim of providing a clear specification with minimal footgun potential.

This is achieved by using the recursive proofs of Mina extensively:
seperating the "creation" of the credential from the "presentation" of the credential:
besides unifying the presentation proof, it also allows doing most of the expensive operations (e.g. verifying an RSA signature using SHA256 and parsing a JSON object) once during the creation of the credential.

At the highest possible level of abstraction, Mina credentials
are a set of "attributes" (e.g. name, age, SSN) attested to by a "issuer".
The issuer is an opaque entity (a hash) and may identify e.g. the root of a Merkle tree,
the root authorities of a PKI, the hash of Google's OAuth public key, etc.
By exploiting the recursive proofs of Mina, this diverse set of issuers / applications
can be brought into a standard form: a SNARK on a hash of the attributes.
All these credentials can also be stored/verified/used in the same way.
This provides a plug-and-play system:
allowing developers to create new credential types and application logics seperately, combining them in a safe, modular way.

# Related Works & Systems

## [zkLogin](https://docs.sui.io/concepts/cryptography/zklogin)

zkLogin

## [zkPassport](https://zkpassport.id/)

zkPassport is based

## [World ID and Semaphore](https://worldcoin.org/blog/worldcoin/intro-zero-knowledge-proofs-semaphore-application-world-id)


The goal of Mina credentials is broader than these systems and must enable
the implementation of these systems within the Mina ecosystem.

# Design Rational

The cryptography team considered two options for the presentation proof.

1. Credentials are "bearer tokens": simply knowing the credential is sufficient to present it.
2. Credentials are associate attributes/capabilities to public keys.

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

Using the context of the presentation as an public input to the proof:
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

Again, using the context as an public input to the proof: but now the context is also signed by the owner
and the signature is verified in-circuit.

## Justification

We deemed that the additional complexity of the second option,
an in-circuit verification of a native signature,
is outweighed by the following benefits:

- Allow use of existing infrastructure for key management.
  Including hardware enclaves and the ability to authortize presentations efficiently using MPC:
  authortization requires the parties to threshold sign using Schnorr.

- Outsourcing the computation of the proofs is possible at the cost of privacy:
  the user must reveal the credential and the context to the prover, but the prover cannot impersonate the user or change the intented action.
  This is useful in scenarios where the prover is a resource-constrained device,
  this is useful in applications such as zkLogin, where for practicality reasons, the proving is outsourced to a third party in practice.
  We want to allow the Mina ecosystem this option should it be relevant to particular applications.

- A compromise of the credential object itself does not allow impersonation.

- Easy integration with the existing Nullifier system within Mina: every credential comes with a public key
  and nullifiers can be computed / exposed against this public key to allow linkability when desired.

- From a theorectical/robustness perspective, a small benefit is that we can assume weaker properties of the proof system:
  the first scheme requires [(weak) simulation extractability](https://eprint.iacr.org/2020/1306.pdf) since the "context".

We obtain a design in which the SNARK serves only to hide the
