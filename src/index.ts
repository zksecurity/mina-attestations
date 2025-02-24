export { Spec, Claim, Constant } from './program-spec.ts';
export { Spec as PresentationSpec } from './program-spec.ts';
export { Operation, type Node } from './operation.ts';
export type { CredentialSpec, StoredCredential } from './credential.ts';
export type { NativeWitness } from './credential-native.ts';
export type { ImportedWitness } from './credential-imported.ts';
export { Credential } from './credential-index.ts';
export {
  Presentation,
  PresentationRequest,
  HttpsRequest,
  ZkAppRequest,
  type PresentationRequestType,
} from './presentation.ts';
export { assert } from './util.ts';
export { DynamicArray } from './dynamic/dynamic-array.ts';
export { StaticArray } from './dynamic/static-array.ts';
export { DynamicBytes } from './dynamic/dynamic-bytes.ts';
export { DynamicString } from './dynamic/dynamic-string.ts';
export { DynamicRecord } from './dynamic/dynamic-record.ts';
export {
  hashDynamic,
  hashDynamicWithPrefix,
  log,
  toValue,
} from './dynamic/dynamic-hash.ts';
export { Schema } from './dynamic/schema.ts';
export { PrettyPrinter } from './pretty-printer.ts';

export type {
  StoredCredentialJSON,
  CredentialSpecJSON,
  PresentationRequestJSON,
  SpecJSON,
  NodeJSON,
} from './validation.ts';
