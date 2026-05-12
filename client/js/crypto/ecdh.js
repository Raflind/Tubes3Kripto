function deriveSharedKey(privateKey, publicKey) {
  return window.crypto.subtle.deriveBits(
    {
      name: "X25519",
      public: publicKey,
    },
    privateKey,
    256,
  );
}

async function deriveAESKey(sharedSecret) {
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedSecret,
    "HKDF",
    false,
    ["deriveKey"],
  );

  return await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode(
        crypto.getRandomValues(new Uint8Array(16)),
      ),
      info: new TextEncoder().encode("aes-key"),
    },
    hkdfKey,
    {
      name: "AES-CBC",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"],
  );
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
