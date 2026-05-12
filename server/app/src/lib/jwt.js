import * as crypto from "crypto";

class JWTError extends Error {}
class InvalidTokenError extends JWTError {}
class InvalidSignError extends JWTError {}
class ExpiredSignError extends JWTError {}

function urlEncode(data) {
  return Buffer.from(data)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function urlDecode(data) {
  data = data.replace(/-/g, "+").replace(/_/g, "/");

  while (data.length % 4 !== 0) {
    data += "=";
  }

  return Buffer.from(data, "base64");
}

function jsonEncode(data) {
  return JSON.stringify(data);
}

function jsonDecode(data) {
  return JSON.parse(data.toString());
}

const algorithm = {
  ES256: {
    hash: "sha256",
    curve: "prime256v1",
    size: 32,
  },

  ES384: {
    hash: "sha384",
    curve: "secp384r1",
    size: 48,
  },

  ES512: {
    hash: "sha512",
    curve: "secp521r1",
    size: 66,
  },
};

export function sign(header, claims, payload, privKey) {
  const allowedHeaderKeys = ["alg", "typ"];

  for (const key of Object.keys(header)) {

      if (!allowedHeaderKeys.includes(key)) {
          throw new JWTError(
              `Parameter ini tidak diperbolehkan: ${key}`
          );
      }
  }

  if (!header.alg) {
    throw new JWTError("alg tidak ditemukan");
  }

  if (!header.typ) {
    throw new JWTError("typ tidak ditemukan");
  }

  if (header.typ !== "JWT") {
    throw new JWTError("Harus JWT");
  }

  const alg = header.alg;

  if (!(alg in algorithm)) {
    throw new JWTError("Algoritma tidak dapat digunakan");
  }

  const config = algorithm[alg];

  const fullPayload = {
    ...payload,
    ...claims,
  };

  const encodedHeader = urlEncode(jsonEncode(header));

  const encodedPayload = urlEncode(jsonEncode(fullPayload));

  const headerPayload = `${encodedHeader}.${encodedPayload}`;

  const signature = crypto.sign(config.hash, Buffer.from(headerPayload), {
    key: privKey,
    dsaEncoding: "ieee-p1363",
  });

  const encodedSignature = urlEncode(signature);

  return `${encodedHeader}.` + `${encodedPayload}.` + `${encodedSignature}`;
}

export function verify(jwt, publicKey, options = {}) {
  const parts = jwt.split(".");

  if (parts.length !== 3) {
    throw new InvalidTokenError("Format JWT Salah");
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  let header;
  let payload;

  try {
    header = jsonDecode(urlDecode(encodedHeader));

    payload = jsonDecode(urlDecode(encodedPayload));
  } catch {
    throw new InvalidTokenError("JWT Invalid");
  }

  const alg = header.alg;

  if (!(alg in algorithm)) {
    throw new JWTError("Algoritma tidak disupport");
  }

  if (options.algs && !options.algs.includes(alg)) {
    throw new JWTError("Algoritma tidak diperbolehkan");
  }

  const config = algorithm[alg];

  const headerPayload = `${encodedHeader}.${encodedPayload}`;

  const signature = urlDecode(encodedSignature);

  const valid = crypto.verify(
    config.hash,
    Buffer.from(headerPayload),
    {
      key: publicKey,
      dsaEncoding: "ieee-p1363",
    },
    signature,
  );

  if (!valid) {
    throw new InvalidSignError("Signature Invalid");
  }

  const now = Math.floor(Date.now() / 1000);

  if (!options.ignoreExp) {
    if ("exp" in payload) {
      if (now >= payload.exp) {
        throw new ExpiredSignError("Token expired");
      }
    }
  }

  if (!options.ignoreNbf) {
    if ("nbf" in payload) {
      if (now < payload.nbf) {
        throw new JWTError("Token belum aktif");
      }
    }
  }

  if (options.iss && payload.iss !== options.iss) {
    throw new JWTError("iss Invalid");
  }

  if (options.sub && payload.sub !== options.sub) {
    throw new JWTError("sub Invalid");
  }

  if (options.aud && payload.aud !== options.aud) {
    throw new JWTError("aud Invalid");
  }

  if (options.jti && payload.jti !== options.jti) {
    throw new JWTError("jti invalid");
  }

  return {
    header,
    payload,
    signature: encodedSignature,
  };
}