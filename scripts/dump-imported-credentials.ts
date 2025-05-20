import { Credential } from '../src/credential-index.ts';
import { ZkPass } from '../src/imported.ts';

await ZkPass.compileDependenciesPartial();
const zkPassCredential = await ZkPass.CredentialPartial();
await zkPassCredential.compile();

let json = JSON.stringify(Credential.importedToJSON(zkPassCredential), null, 2);

console.log(json);

let recovered = Credential.importedFromJSON(JSON.parse(json));
console.log(recovered);
