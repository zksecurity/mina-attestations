import { initializeBindings, type PublicKey } from 'o1js';
import {
  createUnsigned,
  type CredentialSpec,
  type CredentialType,
  hashCredential,
  type StoredCredential,
  Unsigned,
} from './credential.ts';
import {
  createNative,
  Native,
  type Witness as NativeWitness,
} from './credential-native.ts';
import {
  Imported,
  type Witness as ImportedWitness,
} from './credential-imported.ts';
import { assert, hasProperty } from './util.ts';
import { type InferNestedProvable, NestedProvable } from './nested.ts';
import {
  deserializeNestedProvableValue,
  serializeNestedProvableValue,
} from './serialize-provable.ts';
import { Schema } from './dynamic/schema.ts';

export { Credential, validateCredential };

/**
 * A credential is a generic piece of data (the "attributes") along with an owner represented by a public key.
 */
type Credential<Data> = { owner: PublicKey; data: Data };

const Credential = {
  Unsigned,
  Native,
  Imported,

  /**
   * Issue a "native" signed credential.
   */
  sign: createNative,

  /**
   * Create a dummy credential with no owner and no signature.
   */
  unsigned: createUnsigned,

  /**
   * Serialize a credential to a JSON string.
   */
  toJSON(credential: StoredCredential) {
    let json = {
      version: credential.version,
      witness:
        credential.witness === undefined
          ? { type: 'unsigned' }
          : serializeNestedProvableValue(credential.witness),
      metadata: credential.metadata,
      credential: serializeNestedProvableValue(credential.credential),
    };
    return JSON.stringify(json);
  },

  /**
   * Deserialize a credential from a JSON string.
   */
  async fromJSON(json: string): Promise<StoredCredential> {
    await initializeBindings();
    let obj = JSON.parse(json);
    return {
      version: obj.version,
      witness: deserializeNestedProvableValue(obj.witness),
      metadata: obj.metadata,
      credential: deserializeNestedProvableValue(obj.credential),
    };
  },

  /**
   * Validate a credential.
   */
  validate: validateCredential,

  /**
   * Serialize the data input to a `signCredential()` call.
   *
   * The resulting string is accepted as input to `Credential.sign()`.
   *
   * Example
   * ```ts
   * let credentialData = { owner: publicKey, data: { name: 'Alice' } };
   * let credentialDataJson = Credential.dataToJSON(credentialData);
   *
   * let credential = Credential.sign(privateKey, credentialDataJson);
   * ```
   */
  dataToJSON<Data>(credential: Credential<Data>) {
    return JSON.stringify(serializeNestedProvableValue(credential));
  },
};

// validating generic credential

type Witness = NativeWitness | ImportedWitness;

async function validateCredential(
  credential: StoredCredential<unknown, unknown, unknown>
) {
  assert(
    credential.version === 'v0',
    `Unsupported credential version: ${credential.version}`
  );

  assert(knownWitness(credential.witness), 'Unknown credential type');

  let spec = getCredentialSpec(credential.witness)(
    Schema.nestedType(credential.credential.data)
  );

  let credHash = hashCredential(credential.credential);
  await spec.verifyOutsideCircuit(credential.witness, credHash);
}

const witnessTypes = new Set<unknown>([
  'native',
  'imported',
] satisfies Witness['type'][]);

function knownWitness(witness: unknown): witness is Witness {
  return hasProperty(witness, 'type') && witnessTypes.has(witness.type);
}

function getCredentialSpec<W extends Witness>(
  witness: W
): <DataType extends NestedProvable>(
  dataType: DataType
) => CredentialSpec<CredentialType, W, InferNestedProvable<DataType>> {
  switch (witness.type) {
    case 'native':
      return Credential.Native as any;
    case 'imported':
      return Credential.Imported.Generic as any;
  }
}
