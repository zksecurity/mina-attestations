import http from 'http';
import { URL } from 'url';
import { requestLogin, verifyLogin } from './action-login.ts';
import { getVotes, requestVote, verifyVote } from './action-voting.ts';
import { requestZkPassVerification, verifyZkPass } from './action-zkpass.ts';
import { issueCredential } from './issue-credential.ts';

// Helper to read request body
async function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

const server = http.createServer(async (req, res) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders);
    res.end();
    return;
  }

  try {
    let url = new URL(req.url!, `https://${req.headers.host}`);
    let path = removeOptionalPathPrefix(url.pathname, '/api');

    // Add CORS headers to all responses
    Object.entries(corsHeaders).forEach(([key, value]) => {
      res.setHeader(key, value);
    });
    res.setHeader('Content-Type', 'application/json');

    // issue credential endpoint
    if (path === '/issue-credential' && req.method === 'POST') {
      let body = await readBody(req);
      console.log('/issue-credential', body);

      let credentialJson = issueCredential(body);

      res.writeHead(200);
      res.end(credentialJson);
      return;
    }

    // login endpoints
    if (path === '/login-request' && req.method === 'GET') {
      console.log('/login-request');

      let request = await requestLogin();

      res.writeHead(200);
      res.end(request);
      return;
    }
    if (path === '/login' && req.method === 'POST') {
      let body = await readBody(req);
      console.log('/login', body.slice(0, 1000));

      await verifyLogin(body);

      res.writeHead(200);
      res.end('');
      return;
    }

    // polling endpoints
    if (path === '/poll-request' && req.method === 'GET') {
      let vote = url.searchParams.get('vote');
      console.log('/voting-request', vote);

      let request = await requestVote(vote);

      res.writeHead(200);
      res.end(request);
      return;
    }
    if (path === '/poll' && req.method === 'POST') {
      let body = await readBody(req);
      console.log('/poll', body.slice(0, 1000));

      let result = await verifyVote(body);
      let votes = getVotes();
      let response = JSON.stringify({ ...votes, ...result });

      res.writeHead(200);
      res.end(response);
      return;
    }

    // zkPass endpoints
    if (path == '/verify-zkpass-request' && req.method === 'GET') {
      console.log('/verify-zkpass-request');

      let request = await requestZkPassVerification();

      res.writeHead(200);
      res.end(request);
      return;
    }

    if (path == '/verify-zkpass' && req.method === 'POST') {
      let body = await readBody(req);
      console.log('/verify-zkpass', body.slice(0, 1000));

      let result = await verifyZkPass(body);

      res.writeHead(200);
      res.end(JSON.stringify(result));
      return;
    }

    // Handle 404
    res.writeHead(404);
    console.log('Not Found:', url.pathname);
    res.end(JSON.stringify({ error: `Not Found: ${url.pathname}` }));
  } catch (error) {
    console.error('Error:', error);
    res.writeHead(400);
    res.end(
      JSON.stringify({
        error: error instanceof Error ? error.message : 'Unknown error',
      })
    );
  }
});

const PORT = 3000;
server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

function removeOptionalPathPrefix(path: string, prefix: string): string {
  // normalize
  if (!path.startsWith('/')) path = '/' + path;
  if (!prefix.startsWith('/')) prefix = '/' + prefix;
  // remove prefix
  return path.startsWith(prefix) ? path.slice(prefix.length) : path;
}
