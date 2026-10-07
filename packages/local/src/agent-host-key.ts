import { createHash, randomUUID } from "node:crypto";
import { calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { ChatGPTError, isObject } from "./errors.js";
import type { StoredAgentHostKey } from "./types.js";

export const agentHostIdPattern = /^urn:ietf:params:oauth:jwk-thumbprint:sha-256:[A-Za-z0-9_-]{43}$/;

const invalidHostKey = () => new ChatGPTError("host_identity_invalid", "The saved agent host key is unavailable or invalid. Restore the encrypted credential file before signing in.");

export function validateAgentHostKey(value: unknown): asserts value is StoredAgentHostKey {
  if (!isObject(value) || Object.keys(value).sort().join(",") !== "crv,d,kty,x,y" ||
      value.kty !== "EC" || value.crv !== "P-256" ||
      ![value.x, value.y, value.d].every((member) => typeof member === "string" &&
        /^[A-Za-z0-9_-]{43}$/.test(member) && Buffer.from(member, "base64url").toString("base64url") === member)) {
    throw invalidHostKey();
  }
}

export async function generateAgentHostKey(): Promise<StoredAgentHostKey> {
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  const jwk = await exportJWK(privateKey);
  validateAgentHostKey(jwk);
  return jwk;
}

export async function loadAgentHostKey(jwk: StoredAgentHostKey | undefined, expectedHostId?: string) {
  validateAgentHostKey(jwk);
  try {
    const publicJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
    const hostId = `urn:ietf:params:oauth:jwk-thumbprint:sha-256:${await calculateJwkThumbprint(publicJwk, "sha256")}`;
    if (expectedHostId !== undefined && expectedHostId !== hostId) throw invalidHostKey();
    return { hostId, publicJwk, privateKey: await importJWK(jwk, "ES256") };
  } catch { throw invalidHostKey(); }
}

export type AgentHostKey = Awaited<ReturnType<typeof loadAgentHostKey>>;

export async function agentHostKeyProof(key: AgentHostKey, tokenUrl: string, fields: URLSearchParams): Promise<string> {
  const grant = fields.get("grant_type");
  const credential = grant === "authorization_code" ? fields.get("code") : grant === "refresh_token" ? fields.get("refresh_token") : null;
  if (!credential) throw new ChatGPTError("invalid_request", "Agent host proof requires an authorization code or refresh token.");
  const hashClaim = grant === "authorization_code" ? "authorization_code_hash" : "refresh_token_hash";
  return new SignJWT({ htm: "POST", htu: tokenUrl, [hashClaim]: createHash("sha256").update(credential, "utf8").digest("base64url") })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: key.publicJwk })
    .setIssuedAt().setJti(randomUUID()).sign(key.privateKey);
}

export function requireAgentHostAcknowledgement(data: Record<string, unknown>, key: AgentHostKey): void {
  if (data.ext_verified_agent_host_id !== key.hostId) {
    throw new ChatGPTError("host_key_proof_unacknowledged", "ChatGPT did not confirm the agent host key. Check that this integration supports key proof before signing in again. Existing credentials have been preserved.");
  }
  // Unverified claims are only a negative compatibility check, never identity evidence.
  let confirmation: unknown;
  try { confirmation = typeof data.access_token === "string" ? decodeJwt(data.access_token).cnf : undefined; } catch { /* Opaque bearer tokens cannot be inspected. */ }
  if (isObject(confirmation) && confirmation.jkt !== undefined) {
    throw new ChatGPTError("host_key_proof_incompatible_token", "This integration requires bearer access tokens. Existing credentials have been preserved.");
  }
}
