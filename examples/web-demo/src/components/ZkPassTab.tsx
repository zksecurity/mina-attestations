import React, { useState } from 'react';
import { Label } from './ui/label';
import TransgateConnect from '@zkpass/transgate-js-sdk';
import type { ZkPassResponseItem } from 'mina-attestations/imported';
import {
  exampleProofAndSchema,
  defaultSchema,
  importZkpassProof,
  defaultAppId,
} from '../interactions/import-credential';
import { CopyableCode } from './ui/copyable-code';

const ZkPassTab: React.FC<{ useMockWallet: boolean }> = ({ useMockWallet }) => {
  const [appId, setAppId] = useState<string>(defaultAppId);
  const [schemaId, setSchemaId] = useState<string>(defaultSchema);
  const [result, setResult] = useState<ZkPassResponseItem | null>(null);
  const [schemaIdWithResult, setSchemaIdWithResult] = useState<
    string | undefined
  >(undefined);

  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<string | undefined>(undefined);
  const [isLoading2, setIsLoading2] = useState<string | undefined>(undefined);
  const [credential, setCredential] = useState<string | null>(null);

  const start = async () => {
    try {
      setError(null);
      setIsLoading('Processing...');

      console.log('Creating connector...');
      const connector = new TransgateConnect(appId);
      console.log('Connector created:', connector);

      console.log('Checking TransGate availability...');
      const isAvailable = await connector.isTransgateAvailable();
      console.log('TransGate available:', isAvailable);

      if (!isAvailable) {
        throw new Error('Please install zkPass TransGate');
      }

      console.log('Launching schema with ID:', schemaId);
      try {
        const res = await connector.launch(schemaId);
        console.log('Launch response:', res);
        setResult(res as any);
        setSchemaIdWithResult(schemaId);
      } catch (launchError) {
        console.error('Launch error:', launchError);
        if (launchError && typeof launchError === 'object') {
          console.error('Launch error details:', {
            name: (launchError as any).name,
            message: (launchError as any).message,
            code: (launchError as any).code,
          });
        }
        throw launchError;
      }
    } catch (err) {
      console.error('Full error object:', err);
      if (err && typeof err === 'object') {
        setError(`Error: ${(err as any).message || 'Unknown error'}`);
      } else {
        setError('An unknown error occurred');
      }
    } finally {
      setIsLoading(undefined);
    }
  };

  async function importCredential(
    schemaId: string,
    result: ZkPassResponseItem
  ) {
    try {
      setIsLoading2('Preparing import...');
      let credential = await importZkpassProof(
        schemaId,
        result,
        useMockWallet,
        setIsLoading2
      );
      setCredential(credential);
    } catch (err) {
      console.error(err);
      setError(
        err instanceof Error ? err.message : 'Failed to create credential'
      );
    } finally {
      setIsLoading2(undefined);
    }
  }

  return (
    <div className="bg-white p-6 rounded-lg shadow-sm space-y-6">
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 p-4 rounded-md">
          {error}
        </div>
      )}

      <div className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="appId">App ID:</Label>
          <input
            id="appId"
            type="text"
            className="w-full p-2 border rounded-md font-mono text-sm"
            value={appId}
            onChange={(e) => setAppId(e.target.value)}
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="schemaId">Schema ID:</Label>
          <input
            id="schemaId"
            type="text"
            className="w-full p-2 border rounded-md font-mono text-sm"
            value={schemaId}
            onChange={(e) => setSchemaId(e.target.value)}
          />
        </div>

        <div className="flex space-x-4">
          <button
            onClick={start}
            disabled={!!isLoading}
            className="flex-1 p-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isLoading ?? 'Start ZkPass Proof'}
          </button>
          <button
            type="button"
            onClick={() => {
              setSchemaIdWithResult(exampleProofAndSchema.schema);
              setResult(exampleProofAndSchema.proof);
            }}
            className="flex-1 p-2 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200"
          >
            Use Example Proof
          </button>
        </div>
      </div>

      {result && schemaIdWithResult && (
        <div className="mt-6 space-y-4">
          <h3 className="text-lg font-semibold">Result:</h3>
          <pre className="bg-gray-100 p-4 rounded-lg overflow-auto max-h-96 text-sm">
            {JSON.stringify(result, null, 2)}
          </pre>
          <button
            onClick={() => importCredential(schemaIdWithResult, result)}
            disabled={!!isLoading2}
            className="w-full p-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isLoading2 ?? 'Import as Credential'}
          </button>
        </div>
      )}

      {credential && (
        <div className="mt-6">
          <CopyableCode value={credential} label="Imported Credential" />
        </div>
      )}
    </div>
  );
};

export default ZkPassTab;
