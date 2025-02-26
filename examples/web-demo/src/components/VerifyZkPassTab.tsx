import { useState } from 'react';
import { useToast } from './ui/toast';
import { verifyZkpassRequest } from '../interactions/presentation-request';

const VerifyZkPassTab = ({ useMockWallet }: { useMockWallet: boolean }) => {
  const [isLoading, setIsLoading] = useState<string | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();

  const handleVerificationRequest = async () => {
    setIsLoading('Loading...');
    setError(null);

    try {
      await verifyZkpassRequest(useMockWallet, setIsLoading);

      toast({
        title: 'Success',
        description: 'ZkPass credential verified successfully',
        className: 'bg-green-50 border border-green-200 text-green-800',
      });
    } catch (error) {
      console.error(error);
      setError(error instanceof Error ? error.message : 'Verification failed');
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
        {isLoading ?? 'Verify ZkPass Credential'}
      </button>
    </div>
  );
};

export default VerifyZkPassTab;
