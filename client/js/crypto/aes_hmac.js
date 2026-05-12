export async function encryptAndSign(plainText, aesKey, hmacKey) {
  const encoder = new TextEncoder();
  const data = encoder.encode(plainText);
  const iv = crypto.getRandomValues(new Uint8Array(16));

  // Enkripsi AES-CBC
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-CBC",
      iv: iv,
    },
    aesKey,
    data,
  );

  // Menghitung HMAC
  const combinedData = _appendBuffer(iv, ciphertext);
  const mac = await crypto.subtle.sign("HMAC", hmacKey, combinedData);

  return {
    iv: _bufferToBase64(iv),
    ciphertext: _bufferToBase64(ciphertext),
    mac: _bufferToBase64(mac),
  };
}

export async function verifyAndDecrypt(payload, aesKey, hmacKey) {
  const iv = _base64ToArrayBuffer(payload.iv);
  const ciphertext = _base64ToArrayBuffer(payload.ciphertext);
  const macTag = _base64ToArrayBuffer(payload.mac);

  // Verifikasi MAC
  const combinedData = _appendBuffer(iv, ciphertext);
  const isValid = await crypto.subtle.verify(
    "HMAC",
    hmacKey,
    macTag,
    combinedData,
  );
  if (!isValid) {
    throw new Error("Invalid input, MAC Verification Failed!");
  }

  // Dekripsi AES-CBC
  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv: iv },
      aesKey,
      ciphertext,
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
  } catch (e) {
    throw new Error("Decryption failed!");
  }
}

// Fungsi menggabungkan buffer untuk input MAC
function _appendBuffer(buffer1, buffer2) {
  const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
  tmp.set(new Uint8Array(buffer1), 0);
  tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
  return tmp.buffer;
}

// Base64 Encoding
export function _bufferToBase64(buffer) {
  let bin = "";
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin);
}
export function _base64ToArrayBuffer(base64) {
  const bin_str = atob(base64);
  const bytes = new Uint8Array(bin_str.length);
  for (let i = 0; i < bin_str.length; i++) {
    bytes[i] = bin_str.charCodeAt(i);
  }
  return bytes.buffer;
}
