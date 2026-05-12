export function deriveSharedKey(privateKey, publicKey) {
  return window.crypto.subtle.deriveBits(
    {
      name: "X25519",
      public: publicKey,
    },
    privateKey,
    256,
  );
}

export async function deriveAESKey(sharedSecret, salt) {
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedSecret,
    "HKDF",
    false,
    ["deriveBits"],
  );

  const keyBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt, // FIX: raw bytes, not TextEncoder'd
      info: new TextEncoder().encode("messaging"),
    },
    hkdfKey,
    512,
  );

  const aesKey = await crypto.subtle.importKey(
    "raw",
    keyBits.slice(0, 32),
    { name: "AES-CBC" },
    false,
    ["encrypt", "decrypt"],
  );

  const hmacKey = await crypto.subtle.importKey(
    "raw",
    keyBits.slice(32, 64),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );

  return { aesKey, hmacKey };
}

export async function generateKeyPair() {
  return crypto.subtle.generateKey(
    {
      name: "X25519",
    },
    true,
    ["deriveKey", "deriveBits"],
  );
}

export async function exportPublicKey(publicKey) {
  const raw = await crypto.subtle.exportKey("raw", publicKey);

  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

export async function exportPrivateKey(privateKey) {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);

  return btoa(String.fromCharCode(...new Uint8Array(pkcs8)));
}

export async function generateStorageKey(password, salt) {
  const encoder = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );

  const keyBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 10000,
      hash: "SHA-256",
    },
    baseKey,
    512,
  );

  const aesKey = await crypto.subtle.importKey(
    "raw",
    keyBits.slice(0, 32),
    "AES-CBC",
    false,
    ["encrypt", "decrypt"],
  );

  const hmacKey = await crypto.subtle.importKey(
    "raw",
    keyBits.slice(32, 64),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign", "verify"],
  );
  return { aesKey, hmacKey };
}

export async function importPrivateKey(base64) {
  const pkcs8 = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "X25519" }, true, [
    "deriveKey",
    "deriveBits",
  ]);
}

export async function importPublicKey(base64) {
  const raw = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("raw", raw, { name: "X25519" }, true, []);
}
