import fs from 'fs';
import path from 'path';
import { Credential } from '../src/credential-index.ts';
import { ZkPass } from '../src/imported.ts';
import type { CredentialSpec } from '../src/credential.ts';
import { VerificationKey } from 'o1js';

const SPECS_TO_DUMP = [
  {
    name: 'ZkPass Credential',
    outputFilename: 'zkpass-credential.json',
    get: async () => {
      await ZkPass.compileDependenciesPartial();
      let cred = await ZkPass.CredentialPartial();
      await cred.compile();
      return cred;
    },
  },
];

// output directory
const GEN_DIR = path.join(process.cwd(), 'scripts', 'gen');

// ensure the gen directory exists
if (!fs.existsSync(GEN_DIR)) {
  fs.mkdirSync(GEN_DIR, { recursive: true });
}

// dump all credential specs
await dumpAllCredentialSpecs();

async function dumpAllCredentialSpecs() {
  console.log(
    `Starting to dump ${SPECS_TO_DUMP.length} credential specs to ${GEN_DIR}`
  );

  for (let specConfig of SPECS_TO_DUMP) {
    try {
      await dumpCredentialSpec(specConfig);
    } catch (error) {
      console.error(`❌ Error processing ${specConfig.name}:`, error);
    }
  }

  console.log(`\nAll credential specs processed.`);
}

async function dumpCredentialSpec(specConfig: {
  name: string;
  outputFilename: string;
  get: () => Promise<{
    spec: CredentialSpec<any, any>;
    verificationKey: VerificationKey | undefined;
  }>;
}) {
  console.log(`\nProcessing: ${specConfig.name}`);

  // Get the spec and verification key
  console.log(`- Compiling and preparing credential...`);
  let credSpec = await specConfig.get();

  // Convert to JSON
  console.log(`- Converting to JSON...`);
  let jsonData = Credential.importedToJSON(credSpec);
  let jsonString = JSON.stringify(jsonData, null, 2);

  // Write to file
  let outputPath = path.join(GEN_DIR, specConfig.outputFilename);
  console.log(`- Writing to ${outputPath}...`);
  fs.writeFileSync(outputPath, jsonString);

  console.log(`✅ ${specConfig.name} saved successfully`);
}
