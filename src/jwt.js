const JWT_EXPECTED_ALG = "HS256";
const JWT_VALIDATION_LEEWAY_SECS = 60;

function decodeJwtSection(section, errorMessage) {
  try {
    return JSON.parse(new TextDecoder().decode(base64UrlDecode(section)));
  } catch {
    throw new Error(errorMessage);
  }
}

export function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function decodeJwtPayloadUnsafe(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return null;
    }
    return decodeJwtSection(parts[1], "Invalid token payload");
  } catch {
    return null;
  }
}

export function getJwtSecret(env) {
  const secret = env.JWT_SECRET?.toString?.() || env.JWT_SECRET;
  if (!secret) {
    throw new Error("JWT_SECRET not configured");
  }
  return secret;
}

export async function verifyHs256Jwt(token, secret) {
  const encoder = new TextEncoder();
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid token format");
  }

  const [headerB64, payloadB64, signatureB64] = parts;
  const header = decodeJwtSection(headerB64, "Invalid token header");

  if (!header || typeof header !== "object" || header.alg !== JWT_EXPECTED_ALG) {
    throw new Error("Invalid token algorithm");
  }

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signature = base64UrlDecode(signatureB64);
  const data = encoder.encode(`${headerB64}.${payloadB64}`);
  const valid = await crypto.subtle.verify("HMAC", key, signature, data);

  if (!valid) {
    throw new Error("Invalid token signature");
  }

  const payload = decodeJwtSection(payloadB64, "Invalid token payload");
  if (!payload || typeof payload !== "object") {
    throw new Error("Invalid token payload");
  }
  if (typeof payload.exp !== "number") {
    throw new Error("Invalid token exp");
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now - JWT_VALIDATION_LEEWAY_SECS) {
    throw new Error("Token expired");
  }

  return payload;
}
