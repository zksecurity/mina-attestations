# Mina Attestations Demo

This folder contains a simple demo website and server which are designed to demonstrate how to use our credentials library in a concrete setting.

**You can try it out at https://mina-attestations-demo.zksecurity.xyz**

Features:

- Server issues signed credentials to people "registering" with their personal data
- Credentials can be stored in your wallet
- "Anonymous Login" presentation allows simply demonstrating that you have a non-expired credential
- "Anonymous Poll" presentation allows people matching certain criteria to vote in a poll. Nullifiers ensure that a single credential only allows you to vote once.
- "ZkPass Integration" is an example for importing a credential from an external system, [https://zkpass.org/]. If you have the ZkPass extension installed, it lets you walk through their zkTLS flow. This produces a zkTLS proof signed by a zkPass validator, and our web UI lets you import that ECDSA signature into a credential.
- For easier testing, users can either use their actual wallet or a mock wallet that is created on the fly by the web page.

Note: The only wallet compatible with Mina Attestations is currently [an unreleased version of Pallad](https://github.com/palladians/pallad/pull/231), which is confirmed to work well with this example app, but still in review.

The server is a plain Node.js server located in `/api-server`. The web app is contained in `/src`.

**Caveat**: For simplicity, and to demonstrate all capabilities of the library, this examples mixes two different entities, _issuer_ and _verifier_, in a single web app. In actual production code, there should obviously be no "issuing endpoint" that simply hands out credentials to users with whatever data they request.

## Try it out locally

```bash
# build `mina-attestations`, from repo root
npm i && npm run build

# start the vite dev server
cd examples/web-demo
npm run dev
```

in another terminal:

```bash
# start api server
cd examples/web-demo/api-server
npm start
```
