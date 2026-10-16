import { createHash, randomUUID } from "node:crypto";
import { calculateJwkThumbprintUri, exportJWK, generateKeyPair, importJWK, SignJWT, jwtVerify, type JWK } from "jose";
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

function isBase64url32(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const bytes = Buffer.from(value, "base64url");
  return bytes.length === 32 && bytes.toString("base64url") === value;
}

export function isHostKeyId(value: string): boolean {
  return value.startsWith(HOST_KEY_PREFIX) && isBase64url32(value.slice(HOST_KEY_PREFIX.length));
}

export async function generateHostKey(): Promise<AgentHostKey> {
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  return { id: await calculateJwkThumbprintUri(publicKey), privateJwk: await exportJWK(privateKey) };
}

export async function validateHostKey(value: unknown): Promise<AgentHostKey> {
  try {
    if (!isObject(value) || typeof value.id !== "string" || !isObject(value.privateJwk)) throw new Error();
    const jwk = value.privateJwk;
    if (jwk.kty !== "EC" || jwk.crv !== "P-256" || Object.keys(jwk).length !== 5 ||
        ![jwk.d, jwk.x, jwk.y].every(isBase64url32)) throw new Error();
    const publicKey = publicJwk(jwk);
    if (value.id !== await calculateJwkThumbprintUri(publicKey)) throw new Error();
    // Check key-pair consistency independently of the runtime's JWK importer.
    const challenge = await new SignJWT({}).setProtectedHeader({ alg: "ES256" }).sign(await importJWK(jwk, "ES256"));
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
    [code ? "authorization_code_hash" : "refresh_token_hash"]: createHash("sha256").update(credential, "utf8").digest("base64url"),
  }).setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: publicJwk(host.privateJwk) })
    .setIssuedAt()
    .setJti(randomUUID())
    .sign(await importJWK(host.privateJwk, "ES256"));
}
