import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { get } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { decodeProtectedHeader, exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT } from 'jose';
import { createChatGPT } from '../dist/index.js';
import { ConnectionStore } from '../dist/storage.js';
import { generateHostKey, isHostKeyId } from '../dist/host-key.js';

const issuer = 'https://auth.openai.com';
const endpoint = `${issuer}/api/accounts/oauth/token`;
const discoveryEndpoint = `${issuer}/oauth/token`;
const prefix = 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:';
const clientId = 'key_demo_client';
const subject = 'key-demo-subject';
const code = 'ac.1.exact+credential/with=unicode-π';
const refreshToken = 'rt.1.exact+refresh/with=unicode-π';
const { privateKey, publicKey } = await generateKeyPair('RS256');
const jwks = { keys: [{ ...await exportJWK(publicKey), kid: 'host-test-key', use: 'sig', alg: 'RS256' }] };
const digest = (value) => createHash('sha256').update(value, 'utf8').digest('base64url');

test('host IDs require a canonical SHA-256 thumbprint URI', () => {
  const thumbprint = 'A'.repeat(43);
  assert.equal(isHostKeyId(prefix + thumbprint), true);
  for (const value of [thumbprint, prefix + 'A'.repeat(42), prefix + thumbprint + '=', prefix + 'A'.repeat(42) + 'B']) {
    assert.equal(isHostKeyId(value), false);
  }
});

// Synthetic authenticated encryption; production supplies an OS-backed provider.
function encryption() {
  const key = randomBytes(32);
  return {
    id: 'test-host-aes-gcm', isAvailable: () => true,
    encrypt(value) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      return Buffer.concat([iv, cipher.update(value, 'utf8'), cipher.final(), cipher.getAuthTag()]);
    },
    decrypt(value) {
      const bytes = Buffer.from(value);
      const decipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12));
      decipher.setAuthTag(bytes.subarray(-16));
      return Buffer.concat([decipher.update(bytes.subarray(12, -16)), decipher.final()]).toString('utf8');
    },
  };
}

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'siwc-host-key-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const provider = encryption();
  const store = new ConnectionStore(directory, provider);
  const config = { appName: 'Key Pair Demo', appId: 'key-pair-demo', redirectPort: 0,
    storageDir: directory, credentialEncryption: provider, keyBinding: true };
  return { directory, filename: join(directory, 'chatgpt-host-key.json'), provider, store, config };
}

function legacyState() {
  const profile = { version: 1, id: 'profile-1', label: 'Saved account', clientId, subject, status: 'connected',
    scopes: ['openid', 'offline_access', 'chatgpt.tokens.use.direct'], savedAt: new Date().toISOString(),
    credentials: { accessToken: 'legacy-access', refreshToken: 'legacy-refresh', expiresAt: Date.now() + 3600_000 } };
  return { version: 2, activeProfileId: 'profile-1', profiles: [profile,
    { ...profile, id: 'profile-2', label: 'Other account', clientId: 'other_registered_client' }], pendingRegistrations: [] };
}

test('a string configuration value cannot accidentally enable key binding', async (t) => {
  const { config } = await fixture(t);
  assert.throws(() => createChatGPT({ ...config, keyBinding: 'false' }), { code: 'invalid_config' });
});

async function callback(authorization) {
  const url = new URL(authorization.searchParams.get('redirect_uri'));
  url.searchParams.set('state', authorization.searchParams.get('state'));
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('code', code);
  await new Promise((resolve, reject) => {
    const request = get(url, (response) => {
      response.resume();
      response.once('end', () => response.statusCode === 200 ? resolve() : reject(new Error('Callback rejected')));
    });
    request.once('error', reject);
  });
}

function mockServer(t, context, { acknowledgement = 'valid', failCodeOnce = false } = {}) {
  const proofs = [];
  let authorization;
  const config = { ...context.config, openBrowser: async (value) => {
    authorization = new URL(value);
    assert.equal(authorization.searchParams.get('ext_agent_host_id')?.startsWith(prefix), true);
    assert.equal(authorization.searchParams.has('dpop_jkt'), false);
    const encrypted = JSON.parse(await readFile(context.filename, 'utf8'));
    const host = JSON.parse(context.provider.decrypt(Buffer.from(encrypted.ciphertext, 'base64')));
    assert.equal(value.includes(host.privateJwk.d), false);
    await callback(authorization);
  } };
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    if (url === `${issuer}/.well-known/openid-configuration`) {
      return Response.json({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: discoveryEndpoint, jwks_uri: `${issuer}/jwks` });
    }
    if (url === `${issuer}/jwks`) return Response.json(jwks);
    if (url === endpoint) {
      assert.equal(options.method, 'POST');
      const header = decodeProtectedHeader(options.headers.DPoP);
      assert.deepEqual(Object.keys(header).sort(), ['alg', 'jwk', 'typ']);
      assert.equal(header.alg, 'ES256');
      assert.equal(header.typ, 'dpop+jwt');
      assert.deepEqual(Object.keys(header.jwk).sort(), ['crv', 'kty', 'x', 'y']);
      assert.equal(header.jwk.kty, 'EC');
      assert.equal(header.jwk.crv, 'P-256');
      const { payload } = await jwtVerify(options.headers.DPoP, await importJWK(header.jwk, 'ES256'), { algorithms: ['ES256'] });
      const hostId = prefix + digest(JSON.stringify({ crv: 'P-256', kty: 'EC', x: header.jwk.x, y: header.jwk.y }));
      if (authorization) assert.equal(hostId, authorization.searchParams.get('ext_agent_host_id'));
      assert.equal(payload.htm, 'POST');
      assert.equal(payload.htu, url);
      assert.equal(Number.isInteger(payload.iat), true);
      assert.ok(Math.abs(Date.now() / 1000 - payload.iat) < 5);
      assert.equal(proofs.some((proof) => proof.jti === payload.jti), false);
      assert.equal(typeof payload.jti, 'string');
      assert.ok(payload.jti.length > 0);
      const grant = options.body.get('grant_type');
      const credential = grant === 'authorization_code' ? code : refreshToken;
      const claim = grant === 'authorization_code' ? 'authorization_code_hash' : 'refresh_token_hash';
      assert.equal(options.body.get(grant === 'authorization_code' ? 'code' : 'refresh_token'), credential);
      assert.equal(payload[claim], digest(credential));
      assert.deepEqual(Object.keys(payload).sort(), [claim, 'htm', 'htu', 'iat', 'jti'].sort());
      proofs.push({ ...payload, hostId });
      if (failCodeOnce && proofs.length === 1) return Response.json({ error: 'invalid_grant' }, { status: 400 });
      const idToken = grant === 'authorization_code' ? await new SignJWT({ iss: issuer, aud: clientId, sub: subject,
        nonce: authorization.searchParams.get('nonce'), iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 })
        .setProtectedHeader({ alg: 'RS256', kid: 'host-test-key' }).sign(privateKey) : undefined;
      return Response.json({ id_token: idToken, access_token: 'key-bound-access', refresh_token: refreshToken, token_type: 'Bearer',
        scope: 'openid offline_access chatgpt.tokens.use.direct', expires_in: 3600,
        ...(acknowledgement === 'missing' ? {} : { ext_verified_agent_host_id: acknowledgement === 'wrong' ? prefix + 'A'.repeat(43) : hostId }) });
    }
    if (url === 'https://api.openai.com/v1/models') {
      assert.equal(options.headers.authorization, 'Bearer key-bound-access');
      assert.equal(options.headers.DPoP, undefined);
      return Response.json({ models: [] });
    }
    assert.fail(`Unexpected request: ${url}`);
  });
  return { config, proofs, authorization: () => authorization };
}

test('enabling key binding leaves an existing UUID session unbound during refresh', async (t) => {
  const context = await fixture(t);
  const legacy = legacyState();
  legacy.profiles[0].credentials.expiresAt = 1;
  const uuid = await context.store.withLock(async () => { await context.store.write(legacy); return context.store.getHostId(); });
  let refreshes = 0;
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    if (url === `${issuer}/.well-known/openid-configuration`) {
      return Response.json({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: discoveryEndpoint, jwks_uri: `${issuer}/jwks` });
    }
    if (url === discoveryEndpoint) {
      refreshes++;
      assert.equal(options.body.get('grant_type'), 'refresh_token');
      assert.equal(options.body.get('refresh_token'), 'legacy-refresh');
      assert.equal(options.headers.DPoP, undefined);
      return Response.json({ access_token: 'refreshed-legacy-access', refresh_token: 'refreshed-legacy-refresh', token_type: 'Bearer', expires_in: 3600 });
    }
    if (url === 'https://api.openai.com/v1/models') {
      assert.equal(options.headers.authorization, 'Bearer refreshed-legacy-access');
      return Response.json({ models: [] });
    }
    assert.fail(`Unexpected request: ${url}`);
  });
  await createChatGPT(context.config).listModels();
  const saved = await context.store.withLock(() => context.store.read());
  assert.equal(refreshes, 1);
  assert.equal(saved.profiles[0].agentHostId, undefined);
  assert.equal(saved.profiles[0].clientId, clientId);
  assert.equal(await context.store.withLock(() => context.store.getHostId()), uuid);
  assert.deepEqual(saved.profiles[1], legacy.profiles[1]);
  await assert.rejects(readFile(context.filename), { code: 'ENOENT' });
});

test('fresh sign-in upgrades one UUID profile and uses its encrypted key after restart, even with keyBinding disabled', async (t) => {
  const context = await fixture(t);
  const legacy = legacyState();
  const uuid = await context.store.withLock(async () => { await context.store.write(legacy); return context.store.getHostId(); });
  const server = mockServer(t, context);
  const client = createChatGPT(server.config);
  assert.equal((await client.getSession()).status, 'connected');
  await client.signIn({ profileId: 'profile-1' });
  assert.equal(server.authorization().searchParams.get('client_id'), clientId);
  const saved = await context.store.withLock(() => context.store.read());
  assert.deepEqual(saved.profiles.find((profile) => profile.id === 'profile-2'), legacy.profiles[1]);
  const upgraded = saved.profiles.find((profile) => profile.id === 'profile-1');
  assert.equal(upgraded.clientId, clientId);
  assert.equal(upgraded.agentHostId, server.proofs[0].hostId);
  assert.equal(await context.store.withLock(() => context.store.getHostId()), uuid);
  upgraded.credentials.expiresAt = Date.now() - 1;
  await context.store.withLock(() => context.store.write(saved));
  const restarted = createChatGPT({ ...server.config, keyBinding: false });
  await restarted.listModels();
  assert.equal(server.proofs.length, 2);
  assert.equal(server.proofs[1].hostId, server.proofs[0].hostId);
  assert.deepEqual(server.proofs.map((proof) => proof.htu), [endpoint, endpoint]);
  assert.equal((await restarted.getSession()).status, 'connected');
  assert.equal(JSON.stringify(await restarted.listProfiles()).includes('privateJwk'), false);
  await restarted.signIn({ profileId: 'profile-1' });
  assert.equal(server.proofs.length, 3);
  assert.equal(server.proofs[2].hostId, server.proofs[0].hostId);
  const reconnected = await context.store.withLock(() => context.store.read());
  assert.equal(reconnected.profiles.find((profile) => profile.id === 'profile-1').agentHostId, upgraded.agentHostId);
});

test('only an explicit sign-in replaces a missing key for a bound profile', async (t) => {
  const context = await fixture(t);
  const host = await context.store.withLock(() => context.store.getHostKey(true));
  const legacy = legacyState();
  legacy.profiles[0].agentHostId = host.id;
  legacy.profiles[0].credentials.expiresAt = 1;
  await context.store.withLock(() => context.store.write(legacy));
  await rm(context.filename);
  const server = mockServer(t, context);
  const client = createChatGPT(server.config);
  await assert.rejects(client.listModels(), { code: 'host_key_unavailable' });
  assert.equal(server.proofs.length, 0);
  assert.deepEqual(await context.store.withLock(() => context.store.read()), legacy);
  await assert.rejects(readFile(context.filename), { code: 'ENOENT' });
  await client.signIn({ profileId: 'profile-1' });
  const saved = await context.store.withLock(() => context.store.read());
  const recovered = saved.profiles.find((profile) => profile.id === 'profile-1');
  assert.equal(server.proofs.length, 1);
  assert.notEqual(recovered.agentHostId, host.id);
  assert.equal(recovered.agentHostId, server.proofs[0].hostId);
  assert.equal(recovered.clientId, clientId);
  assert.equal(recovered.status, 'connected');
  assert.deepEqual(saved.profiles.find((profile) => profile.id === 'profile-2'), legacy.profiles[1]);
});

test('code retry retains the issued registration and host key but signs a fresh proof', async (t) => {
  const context = await fixture(t);
  const server = mockServer(t, context, { failCodeOnce: true });
  await createChatGPT(server.config).signIn();
  assert.equal(server.proofs.length, 2);
  assert.equal(server.proofs[0].hostId, server.proofs[1].hostId);
  assert.equal(server.authorization().searchParams.get('client_id'), clientId);
  const saved = await context.store.withLock(() => context.store.read());
  assert.equal(saved.profiles.length, 1);
  assert.deepEqual(saved.pendingRegistrations, []);
});

for (const acknowledgement of ['missing', 'wrong']) {
  test(`${acknowledgement} acknowledgement cannot establish key binding or replace a saved UUID profile`, async (t) => {
    const context = await fixture(t);
    const legacy = legacyState();
    await context.store.withLock(() => context.store.write(legacy));
    const server = mockServer(t, context, { acknowledgement });
    await assert.rejects(createChatGPT(server.config).signIn({ profileId: 'profile-1' }), { code: 'host_key_not_verified' });
    assert.deepEqual(await context.store.withLock(() => context.store.read()), legacy);
  });
}

test('missing refresh acknowledgement stops the connection without discarding registration', async (t) => {
  const context = await fixture(t);
  const host = await context.store.withLock(() => context.store.getHostKey(true));
  const state = legacyState();
  state.profiles[0].agentHostId = host.id;
  state.profiles[0].credentials = { accessToken: 'old-access', refreshToken, expiresAt: 1 };
  await context.store.withLock(() => context.store.write(state));
  const server = mockServer(t, context, { acknowledgement: 'missing' });
  await assert.rejects(createChatGPT(server.config).listModels(), { code: 'host_key_not_verified' });
  const saved = await context.store.withLock(() => context.store.read());
  assert.equal(saved.profiles[0].status, 'reauth_required');
  assert.equal(saved.profiles[0].clientId, clientId);
  assert.equal(saved.profiles[0].credentials, undefined);
});

test('host private key is encrypted, stable, and stored with owner-only permissions', async (t) => {
  const { directory, filename, provider, store } = await fixture(t);
  const host = await store.withLock(() => store.getHostKey(true));
  const raw = await readFile(filename, 'utf8');
  assert.equal(raw.includes(host.privateJwk.d), false);
  assert.equal(raw.includes('privateJwk'), false);
  const restarted = new ConnectionStore(directory, provider);
  assert.deepEqual(await restarted.withLock(() => restarted.getHostKey()), host);
  if (process.platform !== 'win32') assert.equal((await stat(filename)).mode & 0o777, 0o600);
});

for (const failure of ['missing', 'tampered', 'wrong-key', 'unavailable']) {
  test(`${failure} host key blocks refresh without generating a replacement or changing the saved session`, async (t) => {
    const context = await fixture(t);
    const host = await context.store.withLock(() => context.store.getHostKey(true));
    const state = legacyState();
    state.profiles[0].agentHostId = host.id;
    state.profiles[0].credentials.expiresAt = 1;
    await context.store.withLock(() => context.store.write(state));
    if (failure === 'missing') await rm(context.filename);
    else if (failure === 'tampered') {
      const envelope = JSON.parse(await readFile(context.filename, 'utf8'));
      const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
      ciphertext[ciphertext.length - 1] ^= 1;
      envelope.ciphertext = ciphertext.toString('base64');
      await writeFile(context.filename, JSON.stringify(envelope));
    } else if (failure === 'wrong-key') {
      await rm(context.filename);
      await context.store.withLock(() => context.store.getHostKey(true));
    } else context.provider.isAvailable = () => false;
    const before = await readFile(join(context.directory, 'chatgpt-auth.json'), 'utf8');
    const keyBefore = failure === 'missing' ? undefined : await readFile(context.filename, 'utf8');
    t.mock.method(globalThis, 'fetch', () => assert.fail('No token request without the matching private key'));
    const expected = failure === 'unavailable' ? 'storage_encryption_unavailable' : failure === 'tampered' ? 'storage_decryption_failed' : 'host_key_unavailable';
    await assert.rejects(createChatGPT(context.config).listModels(), { code: expected });
    assert.equal(await readFile(join(context.directory, 'chatgpt-auth.json'), 'utf8'), before);
    if (failure === 'missing') await assert.rejects(readFile(context.filename), { code: 'ENOENT' });
    else assert.equal(await readFile(context.filename, 'utf8'), keyBefore);
  });
}

test('a mismatched private/public key is rejected without overwriting the encrypted host file', async (t) => {
  const { store, filename, provider } = await fixture(t);
  const host = await store.withLock(() => store.getHostKey(true));
  host.privateJwk.d = (await generateHostKey()).privateJwk.d;
  const raw = JSON.stringify({ version: 1, provider: provider.id, ciphertext: provider.encrypt(JSON.stringify(host)).toString('base64') });
  await writeFile(filename, raw);
  await assert.rejects(store.withLock(() => store.getHostKey(true)), { code: 'host_identity_invalid' });
  assert.equal(await readFile(filename, 'utf8'), raw);
});
