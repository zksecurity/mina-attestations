import {
    Field,
    MerkleMap,
    MerkleTree,
    MerkleWitness,
    Poseidon,
    Provable,
    Struct,
    ZkProgram,
  } from 'o1js';
  import { Credential } from '../credential-index.js';
  import { DynamicRecord } from '../dynamic/dynamic-record.js';
  
  /**
   * Create a MerkleWitness class with the specified height
   */
  function createMerkleWitness(height: number) {
    return MerkleWitness(height);
  }
  
  /**
   * MerkleProof implementation for proving membership in Merkle trees and maps
   */
  export const MerkleProof = {
    /**
     * Create a credential specification for MerkleTree proofs
     * 
     * @param options.treeHeight Height of the Merkle tree
     * @param options.maxEntries Maximum number of entries in the data record
     * @returns A credential spec for MerkleTree proofs
     */
    async Tree({ 
      treeHeight = 20, 
      maxEntries = 100 
    }: { 
      treeHeight?: number;
      maxEntries?: number;
    } = {}) {
      // Create witness for the data's position in the tree
      const Witness = createMerkleWitness(treeHeight);
      
      // Define the program for creating the Merkle proof
      const MerkleProofProgram = ZkProgram({
        name: 'MerkleTreeProof',
        publicInput: {
          ownerPublicKey: Provable.PublicKey,
          root: Field,
        },
        publicOutput: Struct({
          owner: Provable.PublicKey,
          data: {
            root: Field,
          },
        }),
        methods: {
          prove: {
            privateInputs: [Witness, Provable.Any],
            method(publicInput: { ownerPublicKey: Provable.PublicKey; root: Field }, witness: any, data: any) {
              // Hash the data to get the leaf value
              const dataHash = Poseidon.hash(Provable.toFields(data));
              
              // Verify the witness path leads to the claimed root
              const computedRoot = witness.calculateRoot(dataHash);
              computedRoot.assertEquals(publicInput.root);
              
              return {
                publicOutput: {
                  owner: publicInput.ownerPublicKey,
                  data: {
                    root: publicInput.root,
                  },
                },
              };
            },
          },
        },
      });
  
      // Create imported credential specification from program
      const ImportedCred = await Credential.Imported.fromProgram(MerkleProofProgram);
      
      // Compile the verification key
      const verificationKey = await ImportedCred.compile();
      
      return {
        spec: ImportedCred.spec,
        verificationKey,
        
        /**
         * Create a credential proving inclusion in a Merkle tree
         * 
         * @param params.owner Credential owner
         * @param params.tree MerkleTree containing the data
         * @param params.data The data to prove inclusion for
         * @param params.index Index of the data in the tree
         * @returns A credential containing the Merkle root and proof
         */
        async create(params: {
          owner: { toPublicKey(): any };
          tree: MerkleTree;
          data: any;
          index: bigint;
        }) {
          const { owner, tree, data, index } = params;
          
          // Verify that the tree height matches our expected height
          if (tree.height !== treeHeight) {
            throw new Error(`Tree height mismatch: expected ${treeHeight}, got ${tree.height}`);
          }
          
          // Create witness for the data's position in the tree
          const witness = tree.getWitness(index);
          
          // Dynamically handle any data structure
          const Dynamic = DynamicRecord(data, { maxEntries });
          const dynamicData = Dynamic.from(data);
          
          // Hash the data to get the leaf value
          const dataHash = Poseidon.hash(Provable.toFields(dynamicData));
          
          // Verify the leaf matches what's in the tree
          const root = tree.getRoot();
          const WitnessClass = Witness; // Use the class directly
          const pathWitness = new WitnessClass(witness);
          const expectedRoot = pathWitness.calculateRoot(dataHash);
          
          if (!root.equals(expectedRoot).toBoolean()) {
            throw new Error('Data hash does not match the tree leaf at the given index');
          }
          
          // Generate the proof
          const { proof } = await MerkleProofProgram.prove(
            {
              ownerPublicKey: owner.toPublicKey(),
              root,
            },
            pathWitness,
            dynamicData
          );
          
          return ImportedCred.fromProof(proof, verificationKey);
        }
      };
    },
    
    /**
     * Create a credential specification for MerkleMap proofs
     * 
     * @param options.maxEntries Maximum number of entries in the data record
     * @returns A credential spec for MerkleMap proofs
     */
    async Map({ maxEntries = 100 }: { maxEntries?: number } = {}) {
      // Define the program for creating the Merkle map proof
      const MerkleMapProofProgram = ZkProgram({
        name: 'MerkleMapProof',
        publicInput: {
          ownerPublicKey: Provable.PublicKey,
          root: Field,
          key: Field,
        },
        publicOutput: Struct({
          owner: Provable.PublicKey,
          data: {
            root: Field,
            key: Field,
          },
        }),
        methods: {
          prove: {
            privateInputs: [Provable.Any, Provable.Witness],
            method(publicInput: { ownerPublicKey: Provable.PublicKey; root: Field; key: Field }, data: any, witness: any) {
              // Hash the data to get the value
              const dataHash = Poseidon.hash(Provable.toFields(data));
              
              // Verify the witness path leads to the claimed root
              const [computedRoot, computedKey] = witness.computeRootAndKey(dataHash);
              computedRoot.assertEquals(publicInput.root);
              computedKey.assertEquals(publicInput.key);
              
              return {
                publicOutput: {
                  owner: publicInput.ownerPublicKey,
                  data: {
                    root: publicInput.root,
                    key: publicInput.key,
                  },
                },
              };
            },
          },
        },
      });
  
      // Create imported credential specification from program
      const ImportedCred = await Credential.Imported.fromProgram(MerkleMapProofProgram);
      
      // Compile the verification key
      const verificationKey = await ImportedCred.compile();
      
      return {
        spec: ImportedCred.spec,
        verificationKey,
        
        /**
         * Create a credential proving inclusion in a Merkle map
         * 
         * @param params.owner Credential owner
         * @param params.map MerkleMap containing the data
         * @param params.data The data to prove inclusion for
         * @param params.key Key of the data in the map
         * @returns A credential containing the Merkle root and proof
         */
        async create(params: {
          owner: { toPublicKey(): any };
          map: MerkleMap;
          data: any;
          key: Field;
        }) {
          const { owner, map, data, key } = params;
          
          // Get witness for the data's position in the map
          const witness = map.getWitness(key);
          
          // Dynamically handle any data structure
          const Dynamic = DynamicRecord(data, { maxEntries });
          const dynamicData = Dynamic.from(data);
          
          // Hash the data to get the value
          const dataHash = Poseidon.hash(Provable.toFields(dynamicData));
          
          // Verify the data matches what's in the map
          const value = map.get(key);
          if (!value.equals(dataHash).toBoolean()) {
            throw new Error('Data hash does not match the map value at the given key');
          }
          
          // Generate the proof
          const { proof } = await MerkleMapProofProgram.prove(
            {
              ownerPublicKey: owner.toPublicKey(),
              root: map.getRoot(),
              key,
            },
            dynamicData,
            witness
          );
          
          return ImportedCred.fromProof(proof, verificationKey);
        }
      };
    }
  };