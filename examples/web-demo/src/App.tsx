import React, { useState, useEffect } from 'react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from './components/ui/tabs';
import { Switch } from './components/ui/switch';
import { Label } from './components/ui/label';
import { useToast, ToastProvider } from './components/ui/toast';
import AnonymousPoll from './components/poll';
import ZkPassTab from './components/ZkPassTab';
import VerifyZkPassTab from './components/VerifyZkPassTab';
import { CopyableCode } from './components/ui/copyable-code';
import {
  getPublicKey,
  obtainCredential,
} from './interactions/obtain-credential';
import { loginRequest } from './interactions/presentation-request';
import { storeCredential } from './interactions/store-credential';

const IssueCredentialsForm: React.FC<{
  useMockWallet: boolean;
  formData: {
    owner: string;
    name: string;
    birthDate: string;
    nationality: string;
  };
  onFormDataChange: (formData: any) => void;
  onSubmit: () => void;
  onClear: () => void;
}> = ({ formData, onFormDataChange, onSubmit, onClear }) => {
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit();
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="ownerPublicKey">Your Public Key</Label>
        <input
          id="ownerPublicKey"
          type="text"
          required
          className="w-full p-2 border rounded-md font-mono text-sm"
          value={formData.owner}
          onChange={(e) =>
            onFormDataChange({ ...formData, ownerPublicKey: e.target.value })
          }
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="name">Name</Label>
        <input
          id="name"
          type="text"
          required
          className="w-full p-2 border rounded-md"
          value={formData.name}
          onChange={(e) =>
            onFormDataChange({ ...formData, name: e.target.value })
          }
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="birthDate">Birth Date</Label>
        <input
          id="birthDate"
          type="date"
          required
          className="w-full p-2 border rounded-md"
          value={formData.birthDate}
          onChange={(e) =>
            onFormDataChange({ ...formData, birthDate: e.target.value })
          }
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="nationality">Nationality</Label>
        <input
          id="nationality"
          type="text"
          required
          className="w-full p-2 border rounded-md"
          value={formData.nationality}
          onChange={(e) =>
            onFormDataChange({ ...formData, nationality: e.target.value })
          }
        />
      </div>

      <div className="flex space-x-4">
        <button
          type="submit"
          className="flex-1 p-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
        >
          Obtain Credential
        </button>
        <button
          type="button"
          onClick={(e) => {
            e.preventDefault();
            onClear();
          }}
          className="flex-1 p-2 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200"
        >
          Clear Form
        </button>
      </div>
    </form>
  );
};

const StoreCredentialTab: React.FC<{ useMockWallet: boolean }> = ({
  useMockWallet,
}) => {
  const [credential, setCredential] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isStoring, setIsStoring] = useState(false);
  const { toast } = useToast();

  const handleStore = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsStoring(true);
    setError(null);

    try {
      await storeCredential(useMockWallet, credential);
      toast({
        title: 'Success',
        description: 'Credential stored successfully',
        className: 'bg-green-50 border border-green-200 text-green-800',
      });
      setCredential(''); // Clear the form after success
    } catch (error) {
      setError(error instanceof Error ? error.message : 'An error occurred');
    } finally {
      setIsStoring(false);
    }
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow-sm space-y-6">
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 p-4 rounded-md">
          {error}
        </div>
      )}

      <form onSubmit={handleStore} className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="credential">Paste your credential</Label>
          <textarea
            id="credential"
            required
            className="w-full p-3 border rounded-md font-mono text-sm min-h-[120px]"
            value={credential}
            onChange={(e) => setCredential(e.target.value)}
            placeholder={
              '{"version":"v0","witness":{"type":"native","issuer":...'
            }
          />
        </div>

        <button
          type="submit"
          disabled={isStoring}
          className="w-full p-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isStoring ? 'Storing...' : 'Store Credential'}
        </button>
      </form>
    </div>
  );
};

const LoginTab: React.FC<{ useMockWallet: boolean }> = ({ useMockWallet }) => {
  const [isLoading, setIsLoading] = useState<string | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();

  const handleVerificationRequest = async () => {
    setIsLoading('Loading...');
    setError(null);

    try {
      await loginRequest(useMockWallet, setIsLoading);

      toast({
        title: 'Success',
        description: 'Login successful',
        className: 'bg-green-50 border border-green-200 text-green-800',
      });
    } catch (error) {
      console.error(error);
      setError(error instanceof Error ? error.message : 'Login failed');
    } finally {
      setIsLoading(undefined);
    }
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow-sm space-y-6">
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 p-4 rounded-md">
          {error}
        </div>
      )}

      <button
        onClick={handleVerificationRequest}
        disabled={!!isLoading}
        className="w-full p-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {isLoading ?? 'Anonymous Login'}
      </button>
    </div>
  );
};

const App: React.FC = () => {
  const [useMockWallet, setUseMockWallet] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [issuedCredential, setIssuedCredential] = useState<string | null>(null);

  const [formData, setFormData] = useState({
    owner: '',
    name: '',
    birthDate: '',
    nationality: '',
  });

  const handleClearForm = () => {
    setFormData({
      owner: '',
      name: '',
      birthDate: '',
      nationality: '',
    });
    setIssuedCredential(null);
    setError(null);
  };

  const handleSubmitForm = async () => {
    try {
      const result = await obtainCredential(formData.owner, {
        name: formData.name,
        birthDate: new Date(formData.birthDate).getTime(),
        nationality: formData.nationality,
      });
      setIssuedCredential(result);
      setError(null);
    } catch (error) {
      console.error(error);
      setError(error instanceof Error ? error.message : 'An error occurred');
      setIssuedCredential(null);
    }
  };

  useEffect(() => {
    const fetchPublicKey = async () => {
      try {
        const key = await getPublicKey(useMockWallet);
        setFormData({ ...formData, owner: key });
        setError(null);
      } catch (error) {
        setError(
          error instanceof Error ? error.message : 'Failed to fetch public key'
        );
      }
    };

    fetchPublicKey();
  }, [useMockWallet]);

  return (
    <ToastProvider>
      <div className="min-h-screen bg-gray-50">
        <header className="bg-white border-b border-gray-200">
          <div className="container mx-auto px-4 py-4">
            <div className="flex justify-between items-center">
              <h1 className="text-2xl font-semibold text-gray-900">
                Mina Attestations Demo
              </h1>

              <div className="flex items-center space-x-2">
                <Switch
                  id="wallet-mode"
                  checked={useMockWallet}
                  onCheckedChange={setUseMockWallet}
                />
                <Label htmlFor="wallet-mode">
                  {useMockWallet ? 'Using mock wallet' : 'Using your wallet'}
                </Label>
              </div>
            </div>
          </div>
        </header>

        <main className="container mx-auto px-4 py-8">
          <Tabs defaultValue="issue" className="w-full">
            <div className="w-full overflow-auto scrollbar-none">
              <TabsList className="inline-flex min-w-full w-auto">
                <TabsTrigger value="issue" className="flex-1 min-w-[120px]">
                  Obtain Credential
                </TabsTrigger>
                <TabsTrigger value="store" className="flex-1 min-w-[120px]">
                  Store Credential
                </TabsTrigger>
                <TabsTrigger value="verify" className="flex-1 min-w-[120px]">
                  Anonymous Login
                </TabsTrigger>
                <TabsTrigger value="poll" className="flex-1 min-w-[120px]">
                  Anonymous Poll
                </TabsTrigger>
                <TabsTrigger value="zkpass" className="flex-1 min-w-[120px]">
                  ZkPass Credential
                </TabsTrigger>
                <TabsTrigger
                  value="verify-zkpass"
                  className="flex-1 min-w-[120px]"
                >
                  Verify ZkPass
                </TabsTrigger>
              </TabsList>
            </div>

            <TabsContent value="issue" className="mt-6">
              <div className="bg-white p-6 rounded-lg shadow-sm divide-gray-200">
                {error && (
                  <div className="bg-red-50 border border-red-200 text-red-700 p-4 rounded-md mb-6">
                    {error}
                  </div>
                )}

                <h2 className="text-xl font-semibold text-gray-900 mb-6">
                  Enter credential data
                </h2>
                <IssueCredentialsForm
                  useMockWallet={useMockWallet}
                  formData={formData}
                  onFormDataChange={setFormData}
                  onSubmit={handleSubmitForm}
                  onClear={handleClearForm}
                />

                {issuedCredential && (
                  <div className="mt-6">
                    <CopyableCode
                      value={issuedCredential}
                      label="Issued Credential"
                    />
                  </div>
                )}
              </div>
            </TabsContent>

            <TabsContent value="store" className="mt-6">
              <StoreCredentialTab useMockWallet={useMockWallet} />
            </TabsContent>

            <TabsContent value="verify" className="mt-6">
              <LoginTab useMockWallet={useMockWallet} />
            </TabsContent>

            <TabsContent value="poll" className="mt-6">
              <AnonymousPoll useMockWallet={useMockWallet} />
            </TabsContent>

            <TabsContent value="zkpass" className="mt-6">
              <ZkPassTab useMockWallet={useMockWallet} />
            </TabsContent>

            <TabsContent value="verify-zkpass" className="mt-6">
              <VerifyZkPassTab useMockWallet={useMockWallet} />
            </TabsContent>
          </Tabs>
        </main>
      </div>
    </ToastProvider>
  );
};

export default App;
