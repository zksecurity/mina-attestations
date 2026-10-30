import { Field, Poseidon, Provable, Struct, ZkProgram } from 'o1js';
import { Credential } from '../credential-index.js';
import { DynamicRecord } from '../dynamic/dynamic-record.js';

/**
 * BlindingCommitment implementation
 * 
 * Allows a user to commit to any data without revealing it,
 * with optional blinding randomness for stronger hiding properties.
 */
export const BlindingCommitment = {
  /**
   * Create a credential specification for blinding commitments
   * 
   * @param options.maxEntries Maximum number of entries in the data record
   * @returns A credential spec for blinding commitments
   */
  async Credential({ maxEntries = 100 }: { maxEntries?: number } = {}) {
    // Define the program for creating the commitment
    const CommitmentProgram = ZkProgram({
      name: 'BlindingCommitment',
      publicInput: {
        ownerPublicKey: Provable.PublicKey,
        blinding: Field,
      },
      publicOutput: Struct({
        owner: Provable.PublicKey,
        data: {
          commitment: Field,
        },
      }),
      methods: {
        create: {
          privateInputs: [Provable.Any],
          method(publicInput: { ownerPublicKey: Provable.PublicKey; blinding: Field }, privateData: any) {
            // Create commitment as hash of data and blinding factor
            const commitment = Poseidon.hash([
              ...Provable.toFields(privateData),
              publicInput.blinding,
            ]);

            return {
              publicOutput: {
                owner: publicInput.ownerPublicKey,
                data: {
                  commitment,
                },
              },
            };
          },
        },
      },
    });

    // Create imported credential specification from program
    const ImportedCred = await Credential.Imported.fromProgram(CommitmentProgram);
    
    // Compile the verification key
    const verificationKey = await ImportedCred.compile();
    
    return {
      spec: ImportedCred.spec,
      verificationKey,
      
      /**
       * Create a blinding commitment credential
       * 
       * @param params.owner Owner of the credential
       * @param params.data Data to commit to
       * @param params.blinding Optional blinding factor (defaults to random)
       * @returns A credential containing the commitment
       */
      async create(params: {
        owner: { toPublicKey(): any };
        data: any;
        blinding?: Field;
      }) {
        const { owner, data, blinding = Field.random() } = params;
        
        // Dynamically handle any data structure
        const Dynamic = DynamicRecord(data, { maxEntries });
        const dynamicData = Dynamic.from(data);
        
        // Generate the proof
        const { proof } = await CommitmentProgram.create(
          {
            ownerPublicKey: owner.toPublicKey(),
            blinding,
          },
          dynamicData
        );
        
        return ImportedCred.fromProof(proof, verificationKey);
      },
      
      /**
       * Verify a commitment against original data and blinding
       * 
       * @param credential The commitment credential
       * @param data Original data to verify
       * @param blinding Original blinding factor
       * @returns true if the commitment matches the data and blinding
       */
      async verify(credential: any, data: any, blinding: Field): Promise<boolean> {
        await Credential.validate(credential);
        
        // Recreate the commitment
        const Dynamic = DynamicRecord(data, { maxEntries });
        const dynamicData = Dynamic.from(data);
        
        const expectedCommitment = Poseidon.hash([
          ...Provable.toFields(dynamicData),
          blinding,
        ]);
        
        // Compare with the commitment in the credential
        const actualCommitment = credential.credential.data.commitment;
        return expectedCommitment.equals(actualCommitment).toBoolean();
      }
    };
  }
};