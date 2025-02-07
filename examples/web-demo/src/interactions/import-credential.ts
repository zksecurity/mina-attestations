import { PublicKey } from 'o1js';
import { Credential } from 'mina-attestations';
import { ZkPass, type ZkPassResponseItem } from 'mina-attestations/imported';
import { storeCredential } from './store-credential';
import { getPublicKey } from './obtain-credential';

export { importZkpassProof };

async function importZkpassProof(
  schema: string,
  response: ZkPassResponseItem,
  useMockWallet: boolean,
  log: (msg: string) => void = () => {}
) {
  let owner = await getPublicKey(useMockWallet);

  console.time('zkpass credential');
  let credential = await ZkPass.importCredential(
    PublicKey.fromBase58(owner),
    schema,
    response,
    log
  );
  console.timeEnd('zkpass credential');

  let json = Credential.toJSON(credential);
  await storeCredential(useMockWallet, json);
}
