import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { get } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { calculateJwkThumbprint, decodeProtectedHeader, exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT } from 'jose';
import { createChatGPT } from '../dist/index.js';
import { ConnectionStore } from '../dist/storage.js';
import { agentHostKeyProof, generateAgentHostKey, loadAgentHostKey } from '../dist/agent-host-key.js';

const issuer = 'https://auth.openai.com';
const tokenUrl = `${issuer}/oauth/token`;
const clientId = 'host_proof_test_client';
const subject = 'host-proof-test-subject';
const code = 'synthetic-code+% /雪';
const { publicKey, privateKey } = await generateKeyPair('RS256');
const jwks = { keys: [{ ...await exportJWK(publicKey), kid: 'host-proof-test-key', alg: 'RS256' }] };
const hash = (value) => createHash('sha256').update(value, 'utf8').digest('base64url');
const read = (store) => store.withLock(() => store.read());

// Synthetic authenticated encryption only; applications must use their OS provider.
function encryption() {
  const key = randomBytes(32);
  return {
    id: 'test-host-proof-aes-gcm', isAvailable: () => true,
    encrypt(plaintext) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      return Buffer.concat([iv, cipher.update(plaintext, 'utf8'), cipher.final(), cipher.getAuthTag()]);
    },
    decrypt(ciphertext) {
      const bytes = Buffer.from(ciphertext);
      const cipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12));
      cipher.setAuthTag(bytes.subarray(-16));
      return Buffer.concat([cipher.update(bytes.subarray(12, -16)), cipher.final()]).toString('utf8');
    },
  };
}

async function inspectProof(proof, grant, credential, expectedId) {
  const header = decodeProtectedHeader(proof);
  assert.equal(header.alg, 'ES256');
  assert.equal(header.typ, 'dpop+jwt');
  assert.deepEqual(Object.keys(header.jwk).sort(), ['crv', 'kty', 'x', 'y']);
  const hostId = `urn:ietf:params:oauth:jwk-thumbprint:sha-256:${await calculateJwkThumbprint(header.jwk, 'sha256')}`;
  if (expectedId) assert.equal(hostId, expectedId);
  const { payload } = await jwtVerify(proof, await importJWK(header.jwk, 'ES256'), { algorithms: ['ES256'] });
  assert.equal(payload.htm, 'POST');
  assert.equal(payload.htu, tokenUrl);
  assert.ok(Math.abs(payload.iat - Date.now() / 1000) < 10);
  assert.ok(payload.jti);
  assert.equal(payload[`${grant}_hash`], hash(credential));
  assert.equal(payload[grant === 'refresh_token' ? 'authorization_code_hash' : 'refresh_token_hash'], undefined);
  return { hostId, jti: payload.jti };
}

async function fixture(t, { keyed = false, empty = false } = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'siwc-host-proof-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const provider = encryption();
  const store = new ConnectionStore(directory, provider);
  const state = { version: 2, activeProfileId: 'profile-1', pendingRegistrations: [], profiles: [{
    version: 1, id: 'profile-1', label: 'Test account', clientId, subject, status: 'connected',
    scopes: ['openid', 'offline_access', 'chatgpt.tokens.use.direct'], savedAt: new Date().toISOString(),
    credentials: { accessToken: 'previous-access', refreshToken: 'previous-refresh+% /雪', expiresAt: Date.now() + 30_000 },
  }] };
  if (keyed) {
    state.agentHostKey = await generateAgentHostKey();
    state.profiles[0].agentHostId = (await loadAgentHostKey(state.agentHostKey)).hostId;
  }
  if (!empty) await store.withLock(() => store.write(state));
  const config = { appName: 'Host Proof Test', appId: 'host-proof-test', redirectPort: 0, storageDir: directory, credentialEncryption: provider };
  return { store, state, config, filename: join(directory, 'chatgpt-auth.json') };
}

function mockProvider(t, { token, revoke = () => new Response(null, { status: 200 }) }) {
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    if (url === `${issuer}/.well-known/openid-configuration`) return Response.json({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: tokenUrl, jwks_uri: `${issuer}/jwks`, revocation_endpoint: `${issuer}/revoke` });
    if (url === tokenUrl) return token(options);
    if (url === `${issuer}/jwks`) return Response.json(jwks);
    if (url === `${issuer}/revoke`) return revoke(options);
    if (url === 'https://api.openai.com/v1/models') {
      assert.equal(options.headers.authorization, 'Bearer replacement-access');
      assert.equal(new Headers(options.headers).has('dpop'), false);
      return Response.json({ models: [] });
    }
    assert.fail(`Unexpected request: ${url}`);
  });
}

function tokenResponse(hostId, overrides = {}) {
  return { access_token: 'replacement-access', refresh_token: 'replacement-refresh', token_type: 'Bearer', expires_in: 3600,
    scope: 'openid offline_access chatgpt.tokens.use.direct', ...(hostId ? { ext_verified_agent_host_id: hostId } : {}), ...overrides };
}

function browser(callback) {
  return async (url) => {
    const authorization = new URL(url);
    await callback(authorization);
    const redirect = new URL(authorization.searchParams.get('redirect_uri'));
    redirect.searchParams.set('code', code);
    redirect.searchParams.set('state', authorization.searchParams.get('state'));
    redirect.searchParams.set('client_id', clientId);
    await new Promise((resolve, reject) => {
      get(redirect, (response) => {
        response.resume();
        response.once('end', () => response.statusCode === 200 ? resolve() : reject(new Error('Callback rejected')));
        response.once('error', reject);
      }).once('error', reject);
    });
  };
}

function identity(nonce) {
  return new SignJWT({ iss: issuer, aud: clientId, sub: subject, nonce, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 })
    .setProtectedHeader({ alg: 'RS256', kid: 'host-proof-test-key' }).sign(privateKey);
}

test('proof signs exact decoded credentials with a fresh identifier on each attempt', async () => {
  const key = await loadAgentHostKey(await generateAgentHostKey());
  const ids = new Set();
  for (const grant of ['authorization_code', 'refresh_token']) {
    const fields = new URLSearchParams({ grant_type: grant, [grant === 'authorization_code' ? 'code' : 'refresh_token']: code });
    for (let i = 0; i < 2; i++) ids.add((await inspectProof(await agentHostKeyProof(key, tokenUrl, fields), grant, code, key.hostId)).jti);
  }
  assert.equal(ids.size, 4);
});

test('explicit sign-in migrates a UUID profile only after acknowledgement and preserves encrypted identity across restart and disconnect', async (t) => {
  const { store, state, config, filename } = await fixture(t);
  const legacyHostId = await store.withLock(() => store.getHostId());
  assert.match(legacyHostId, /^urn:uuid:/);
  let authorization;
  let accept = false;
  let activeHostId;
  let expectedRefreshToken = 'replacement-refresh';
  let calls = 0;
  const proofIds = new Set();
  mockProvider(t, { token: async (options) => {
    calls++;
    const grant = options.body.get('grant_type');
    const hostId = activeHostId;
    const credential = grant === 'authorization_code' ? code : expectedRefreshToken;
    assert.equal(options.body.get(grant === 'authorization_code' ? 'code' : 'refresh_token'), credential);
    proofIds.add((await inspectProof(new Headers(options.headers).get('dpop'), grant, credential, hostId)).jti);
    if (grant === 'authorization_code') {
      assert.equal(hash(options.body.get('code_verifier')), authorization.searchParams.get('code_challenge'));
      return Response.json(tokenResponse(accept ? hostId : undefined, { id_token: await identity(authorization.searchParams.get('nonce')) }));
    }
    expectedRefreshToken = `rotated-refresh-${calls}`;
    return Response.json(tokenResponse(hostId, { refresh_token: expectedRefreshToken }));
  } });
  const client = createChatGPT({ ...config, agentHostKeyProof: true, openBrowser: browser(async (url) => {
    authorization = url;
    const saved = await read(store);
    activeHostId = (await loadAgentHostKey(saved.agentHostKey)).hostId;
    assert.equal(url.searchParams.get('ext_agent_host_id'), activeHostId);
    assert.equal(url.searchParams.get('client_id'), clientId);
  }) });
  await assert.rejects(client.signIn(), { code: 'host_key_proof_unacknowledged' });
  assert.deepEqual((await read(store)).profiles, state.profiles);
  assert.equal(calls, 1, 'An unacknowledged proof must not retry without it');
  const firstKey = (await read(store)).agentHostKey;
  accept = true;
  await client.signIn();
  let saved = await read(store);
  assert.deepEqual(saved.agentHostKey, firstKey);
  assert.equal(saved.profiles[0].agentHostId, (await loadAgentHostKey(firstKey)).hostId);
  const raw = await readFile(filename, 'utf8');
  for (const secret of [firstKey.d, 'replacement-access', 'replacement-refresh']) assert.equal(raw.includes(secret), false);
  assert.equal(await store.withLock(() => store.getHostId()), legacyHostId);
  const published = [];
  client.subscribe((session) => published.push(session));
  await client.getSession();
  for (const metadata of [await client.getSession(), await client.listProfiles(), published]) {
    assert.equal(JSON.stringify(metadata).includes(firstKey.d), false);
  }
  for (let rotation = 0; rotation < 2; rotation++) {
    saved = await read(store);
    saved.profiles[0].credentials.expiresAt = Date.now() + 30_000;
    await store.withLock(() => store.write(saved));
    // The key requirement follows the saved profile even when the opt-in is removed.
    await createChatGPT(config).listModels();
  }
  assert.equal(calls, 4);
  assert.equal(proofIds.size, 4);
  await createChatGPT(config).disconnect();
  saved = await read(store);
  assert.deepEqual(saved.agentHostKey, firstKey);
  assert.equal(saved.profiles[0].agentHostId, (await loadAgentHostKey(firstKey)).hostId);
  assert.equal(saved.profiles[0].credentials, undefined);
});

for (const failure of ['missing', 'mismatch', 'invalid_grant', 'server_error', 'bound_access_token']) {
  test(`refresh ${failure} preserves the encrypted profile without an unsigned retry`, async (t) => {
    const { store, state, config, filename } = await fixture(t, { keyed: true });
    const before = await readFile(filename, 'utf8');
    const hostId = state.profiles[0].agentHostId;
    let calls = 0;
    mockProvider(t, { token: async (options) => {
      calls++;
      await inspectProof(new Headers(options.headers).get('dpop'), 'refresh_token', state.profiles[0].credentials.refreshToken, hostId);
      if (failure.endsWith('error') || failure === 'invalid_grant') return Response.json({ error: failure }, { status: failure === 'invalid_grant' ? 400 : 500 });
      const overrides = failure === 'bound_access_token' ? { access_token: await new SignJWT({ cnf: { jkt: 'synthetic' } }).setProtectedHeader({ alg: 'RS256' }).sign(privateKey) } : {};
      return Response.json(tokenResponse(failure === 'missing' ? undefined : failure === 'mismatch' ? 'another-host' : hostId, overrides));
    } });
    await assert.rejects(createChatGPT(config).listModels(), { code: failure === 'bound_access_token' ? 'host_key_proof_incompatible_token' : ['missing', 'mismatch'].includes(failure) ? 'host_key_proof_unacknowledged' : failure });
    assert.equal(calls, 1);
    assert.equal(await readFile(filename, 'utf8'), before);
    assert.deepEqual(await read(store), state);
  });
}

for (const missing of [true, false]) {
  test(`${missing ? 'missing' : 'mismatched'} saved keys never regenerate or send requests for an existing keyed profile`, async (t) => {
    const { store, state, config, filename } = await fixture(t, { keyed: true });
    if (missing) delete state.agentHostKey;
    else state.agentHostKey = await generateAgentHostKey();
    await store.withLock(() => store.write(state));
    const before = await readFile(filename, 'utf8');
    t.mock.method(globalThis, 'fetch', () => assert.fail('No request without the correct key'));
    const client = createChatGPT({ ...config, agentHostKeyProof: true, openBrowser: () => assert.fail('No browser without the correct key') });
    await assert.rejects(client.listModels(), { code: 'host_identity_invalid' });
    await assert.rejects(client.signIn(), { code: 'host_identity_invalid' });
    await assert.rejects(client.signIn({ newProfile: true }), { code: 'host_identity_invalid' });
    assert.equal(await readFile(filename, 'utf8'), before);
  });
}

test('enabling proof does not silently migrate a legacy refresh', async (t) => {
  const { store, config } = await fixture(t);
  let calls = 0;
  mockProvider(t, { token: (options) => {
    calls++;
    assert.equal(new Headers(options.headers).has('dpop'), false);
    return Response.json(tokenResponse());
  } });
  await createChatGPT({ ...config, agentHostKeyProof: true }).listModels();
  assert.equal(calls, 1);
  assert.equal((await read(store)).agentHostKey, undefined);
  assert.equal((await read(store)).profiles[0].agentHostId, undefined);
});

test('a private key in a plaintext legacy file is rejected and preserved', async (t) => {
  const { store, state, filename } = await fixture(t, { keyed: true });
  const plaintext = JSON.stringify(state);
  await writeFile(filename, plaintext, { mode: 0o600 });
  await assert.rejects(read(store), { code: 'storage_encrypted_invalid' });
  assert.equal(await readFile(filename, 'utf8'), plaintext);
});

test('new keyed registration keeps its key requirement while completing sign-in after restart', async (t) => {
  const { store, config } = await fixture(t, { empty: true });
  let authorization;
  let hostId;
  let accept = false;
  let calls = 0;
  const opener = browser(async (url) => {
    authorization = url;
    const saved = await read(store);
    hostId = (await loadAgentHostKey(saved.agentHostKey)).hostId;
    assert.equal(url.searchParams.get('ext_agent_host_id'), hostId);
    assert.equal(url.searchParams.get('client_id'), accept ? clientId : 'dynamic_agent_client');
  });
  mockProvider(t, { token: async (options) => {
    calls++;
    await inspectProof(new Headers(options.headers).get('dpop'), 'authorization_code', code, hostId);
    return Response.json(tokenResponse(accept ? hostId : undefined, { id_token: await identity(authorization.searchParams.get('nonce')) }));
  } });
  await assert.rejects(createChatGPT({ ...config, agentHostKeyProof: true, openBrowser: opener }).signIn(), { code: 'host_key_proof_unacknowledged' });
  const saved = await read(store);
  assert.deepEqual(saved.profiles, []);
  assert.equal(saved.pendingRegistrations[0].agentHostId, hostId);
  assert.equal(saved.pendingRegistrations[0].clientId, clientId);
  accept = true;
  await createChatGPT({ ...config, openBrowser: opener }).signIn({ profileId: saved.pendingRegistrations[0].id });
  const completed = await read(store);
  assert.equal(completed.profiles[0].agentHostId, hostId);
  assert.deepEqual(completed.agentHostKey, saved.agentHostKey);
  assert.deepEqual(completed.pendingRegistrations, []);
  assert.equal(calls, 2);
});

test('new sign-in keeps UUID identity and unsigned token exchange by default', async (t) => {
  const { store, config } = await fixture(t, { empty: true });
  let authorization;
  mockProvider(t, { token: async (options) => {
    assert.equal(new Headers(options.headers).has('dpop'), false);
    return Response.json(tokenResponse(undefined, { id_token: await identity(authorization.searchParams.get('nonce')) }));
  } });
  await createChatGPT({ ...config, openBrowser: browser((url) => {
    authorization = url;
    assert.equal(url.searchParams.has('ext_agent_host_id'), false);
  }) }).signIn();
  const saved = await read(store);
  assert.equal(saved.agentHostKey, undefined);
  assert.equal(saved.profiles[0].agentHostId, undefined);
  assert.match(await store.withLock(() => store.getHostId()), /^urn:uuid:/);
});
