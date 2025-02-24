/**
 * This is the same minimal example used in the README, just keeping it here to check that it stays correct.
 */
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
