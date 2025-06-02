import { publicKey } from './mock-wallet';
import { API_URL } from '../config';

export { getProvider, getPublicKey, obtainCredential };

type Provider = {
  request<M>(params: { method: M; params?: any; context?: any }): Promise<any>;
};
let provider: Provider | undefined;

let providers: any[] = [];
window.addEventListener('mina:announceProvider', (event: any) => {
  console.log('Provider announced', event.detail.info);
  providers.push(event.detail);
});
window.dispatchEvent(new Event('mina:requestProvider'));

function getProvider(): Provider {
  if (provider !== undefined) return provider;

  // find pallad provider
  // TODO: use mina-js for this once it's compatible
  provider = providers.find((provider) => {
    return provider.info.slug === 'pallad';
  })?.provider;
  if (provider === undefined) throw Error('Provider not found');
  return provider;
}

async function getPublicKey(useMockWallet: boolean): Promise<string> {
  if (useMockWallet) return publicKey.toBase58();

  let { result: accounts } =
    await getProvider().request<'mina_requestAccounts'>({
      method: 'mina_requestAccounts',
    });

  if (accounts.length === 0) throw Error('No accounts found');
  return accounts[0];
}

type UserInput = {
  name: string;
  birthDate: number;
  nationality: string;
};

async function obtainCredential(
  owner: string,
  data: UserInput
): Promise<string> {
  let response = await fetch(`${API_URL}/issue-credential`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ owner, data }),
  });

  if (!response.ok) {
    let error = await response.json();
    throw Error(error.error ?? 'Failed to issue credential');
  }
  return await response.text();
}
