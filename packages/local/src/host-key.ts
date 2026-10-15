import { createHash, randomUUID } from "node:crypto";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, SignJWT, jwtVerify, type JWK } from "jose";
import { ChatGPTError, isObject } from "./errors.js";

export const HOST_KEY_PREFIX = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";
export const HOST_KEY_TOKEN_ENDPOINT = "https://auth.openai.com/api/accounts/oauth/token";

/** Internal only: the private key must never leave the trusted local process. */
export interface AgentHostKey {
  id: string;
  privateJwk: JWK;
}

function publicJwk(key: JWK): JWK {
  return { kty: "EC", crv: "P-256", x: key.x, y: key.y };
}

export function isHostKeyId(value: string): boolean {
  if (!value.startsWith(HOST_KEY_PREFIX)) return false;
  const thumbprint = value.slice(HOST_KEY_PREFIX.length);
  return /^[A-Za-z0-9_-]{43}$/.test(thumbprint) && Buffer.from(thumbprint, "base64url").toString("base64url") === thumbprint;
}

export async function generateHostKey(): Promise<AgentHostKey> {
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  return { id: HOST_KEY_PREFIX + await calculateJwkThumbprint(publicJwk(privateJwk)), privateJwk };
}

export async function validateHostKey(value: unknown): Promise<AgentHostKey> {
  try {
    if (!isObject(value) || typeof value.id !== "string" || !isHostKeyId(value.id) || !isObject(value.privateJwk)) throw new Error();
    const jwk = value.privateJwk;
    if (Object.keys(jwk).sort().join(",") !== "crv,d,kty,x,y" || jwk.kty !== "EC" || jwk.crv !== "P-256" ||
        ![jwk.d, jwk.x, jwk.y].every((part) => typeof part === "string" && /^[A-Za-z0-9_-]{43}$/.test(part) && Buffer.from(part, "base64url").toString("base64url") === part)) throw new Error();
    const publicKey = publicJwk(jwk);
    if (value.id !== HOST_KEY_PREFIX + await calculateJwkThumbprint(publicKey)) throw new Error();
    // Import alone need not establish that the supplied public and private values match.
    const challenge = await new SignJWT({ challenge: randomUUID() }).setProtectedHeader({ alg: "ES256" }).sign(await importJWK(jwk, "ES256"));
    await jwtVerify(challenge, await importJWK(publicKey, "ES256"), { algorithms: ["ES256"] });
    return { id: value.id, privateJwk: jwk };
  } catch {
    throw new ChatGPTError("host_identity_invalid", "The saved agent key is invalid. Restore chatgpt-host-key.json before signing in.");
  }
}

export async function createHostKeyProof(host: AgentHostKey, body: URLSearchParams): Promise<string> {
  const code = body.get("grant_type") === "authorization_code";
  const credential = body.get(code ? "code" : "refresh_token");
  if (!credential) throw new ChatGPTError("invalid_config", "The sign-in credential is missing.");
  return new SignJWT({
    htm: "POST",
    htu: HOST_KEY_TOKEN_ENDPOINT,
    iat: Math.floor(Date.now() / 1000),
    jti: randomUUID(),
    [code ? "authorization_code_hash" : "refresh_token_hash"]: createHash("sha256").update(credential, "utf8").digest("base64url"),
  }).setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: publicJwk(host.privateJwk) })
    .sign(await importJWK(host.privateJwk, "ES256"));
}
