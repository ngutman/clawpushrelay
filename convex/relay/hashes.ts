function toBase64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function digestSha256(value: string): Promise<Uint8Array> {
  const payload = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", payload);
  return new Uint8Array(digest);
}

export function normalizeApnsToken(token: string): string {
  return token.trim().replace(/[<>\s]/g, "").toLowerCase();
}

export function apnsTokenSuffix(token: string): string {
  return normalizeApnsToken(token).slice(-8);
}

export async function hashSha256(value: string): Promise<string> {
  return toHex(await digestSha256(value));
}

export async function encodeSha256Base64Url(value: string): Promise<string> {
  return toBase64Url(await digestSha256(value));
}
