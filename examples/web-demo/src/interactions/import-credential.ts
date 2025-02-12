import { PublicKey } from 'o1js';
import { Credential } from 'mina-attestations';
import { ZkPass, type ZkPassResponseItem } from 'mina-attestations/imported';
import { storeCredential } from './store-credential';
import { getPublicKey } from './obtain-credential';
import { IS_DEV } from '../config';

export {
  importZkpassProof,
  defaultAppId,
  defaultSchema,
  exampleProofAndSchema,
};

// created for URL https://mina-attestations-demo.zksecurity.xyz, won't work on a different URL
const appIdProd = '8ebbbb4a-4b17-4709-8a8b-cbfebb3ca9ae';
const schemaIdProd = '319ef6c9e03e47b38fb24420a1f2060c';

// created for URL http://localhost:5173, won't work on a different URL
const appIdDev = 'd15ae509-2b52-4286-920b-41b011b8285c';
const schemaIdDev = '3ec11dea72464d729f76a7d42b7e98b8';

let defaultAppId = IS_DEV ? appIdDev : appIdProd;
let defaultSchema = IS_DEV ? schemaIdDev : schemaIdProd;

// proof created with `schemaIdDev`
const exampleProof: ZkPassResponseItem = {
  taskId: '056cf69572204b03b143a06203c635d3',
  publicFields: [],
  allocatorAddress: '0x19a567b3b212a5b35bA0E3B600FbEd5c2eE9083d',
  publicFieldsHash:
    '0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6',
  allocatorSignature:
    '0x200d38da83a2399d1d075a668cbcbc9c345cce315a14a99ba02d0b5be77e29084bb8a8e62d5a3e8fe4f4a3a14fec0a3608bd680e7f371cbf94b1799a9f53e0601c',
  uHash: '0x39c0117954ac203e492e77cdb14033d99e5fa2763465803784a18df5076bb328',
  validatorAddress: '0xb1C4C1E1Cdd5Cf69E27A3A08C8f51145c2E12C6a',
  validatorSignature:
    '0x8b39bbbd8304f1f80b6b92e83adefa95bb89f99e5725ded54ddbb6276abcaa8c0c7697b842dd82f0361fa07cd2c67016f8497464b7645e99a61909283fe023971c',
};
const exampleProofAndSchema = { proof: exampleProof, schema: schemaIdDev };

async function importZkpassProof(
  schema: string,
  response: ZkPassResponseItem,
  useMockWallet: boolean,
  log: (msg: string) => void = () => {}
) {
  let owner = await getPublicKey(useMockWallet);

  console.time('zkpass credential');
  let credential = await ZkPass.importCredentialPartial(
    PublicKey.fromBase58(owner),
    schema,
    response,
    log
  );
  console.timeEnd('zkpass credential');

  console.log('importZkpassProof vkHash:', credential.witness.vk.hash.toJSON());

  let json = Credential.toJSON(credential);
  await storeCredential(useMockWallet, json);
}
