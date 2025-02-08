import { CredentialData, schema } from './schema.ts';
import { Bytes, Int64, PublicKey } from 'o1js';
import { Credential } from '../../../src/index.ts';
import { getPrivateKey } from './keys.ts';
import { CREDENTIAL_EXPIRY } from './config.ts';

export { issueCredential };

const Bytes16 = Bytes(16);

function issueCredential(userString: string) {
  let userData = CredentialData.parse(JSON.parse(userString));
  let {
    owner,
    data: { name, nationality, birthDate },
  } = userData;

  // random 16 bytes ID
  let id = Bytes16.random();

  let expiresAt = Date.now() + CREDENTIAL_EXPIRY;

  let credential = {
    owner: PublicKey.fromBase58(owner),
    data: schema.from({
      name,
      nationality,
      birthDate: Int64.from(birthDate),
      id,
      expiresAt,
    }),
  };

  let signed = Credential.sign(getPrivateKey(), credential);
  return Credential.toJSON(signed);
}
