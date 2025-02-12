import { PresentationRequest, Presentation } from 'mina-attestations';
import { API_URL } from '../config';
import { getStoredCredentials } from './store-credential';
import { privateKey } from './mock-wallet';

export async function verifyRequest(
  useMockWallet: boolean,
  setStatus: (status: string) => void
) {
  // Get verification request from server
  setStatus('Requesting verification...');
  const response = await fetch(`${API_URL}/verify-zkpass-request`);
  if (!response.ok) throw Error('Failed to get verification request');
  const requestJson = await response.text();

  // Create presentation
  setStatus('Creating presentation...');
  const request = PresentationRequest.fromJSON('https', requestJson);
  const credentials = await getStoredCredentials(useMockWallet);
  const presentation = await Presentation.create(privateKey, {
    request,
    credentials,
    context: { verifierIdentity: window.location.origin },
  });

  // Submit presentation to server
  setStatus('Verifying presentation...');
  const verifyResponse = await fetch(`${API_URL}/verify-zkpass`, {
    method: 'POST',
    body: Presentation.toJSON(presentation),
  });

  if (!verifyResponse.ok) {
    const error = await verifyResponse.json();
    throw Error(error.error || 'Verification failed');
  }
}
