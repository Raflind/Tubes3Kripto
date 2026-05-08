import json
import time
import base64

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256, SHA384, SHA512

class JWTError(Exception):
    pass

class InvalidTokenError(JWTError):
    pass

class InvalidSignError(JWTError):
    pass

class ExpiredSignError(JWTError):
    pass

def url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def url_decode(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def json_encode(data: dict) -> bytes:
    return json.dumps(
        data,
        separators=(',', ':')
    ).encode()


def json_decode(data: bytes) -> dict:
    return json.loads(data.decode())

algorithm = {
    "ES256": {
        "hash": SHA256,
        "curve": "P-256",
        "size": 32,
    },

    "ES384": {
        "hash": SHA384,
        "curve": "P-384",
        "size": 48,
    },

    "ES512": {
        "hash": SHA512,
        "curve": "P-521",
        "size": 66,
    }
}

def sign(
        header: dict,
        claims: dict,
        payload: dict,
        privKey: str
) -> str:
    
    if "alg" not in header:
        raise JWTError("alg tidak ditemukan")
    
    if "typ" not in header:
        raise JWTError("typ tidak ditemukan")
    
    if header["typ"] != "JWT":
        raise JWTError("Harus JWT")
    
    alg = header["alg"]

    if alg not in algorithm:
        raise JWTError("Algoritma tidak dapat digunakan")
    
    config = ""
    
    for algo, info in algorithm.items():
        if algo == alg:
            config = info.copy()

    full_payload = {
        **payload,
        **claims
    }

    encoded_header = url_encode(json_encode(header))
    encoded_payload = url_encode(json_encode(full_payload))

    header_payload = (f"{encoded_header}.{encoded_payload}").encode()

    key = ECC.import_key(privKey)

    hashed = config["hash"].new(header_payload)

    signer = DSS.new(
        key,
        'fips-186-3'
    )

    signature = signer.sign(hashed)


    encoded_sign = url_encode(signature)

    return (f"{encoded_header}.{encoded_payload}.{encoded_sign}")

def verify(
    jwt: str,
    publicKey: str,
    options: dict = None,
):

    if options is None:
        options = {}

    parts = jwt.split('.')

    if len(parts) != 3:
        raise InvalidTokenError(
            "Format JWT Salah"
        )

    encoded_header, encoded_payload, encoded_signature = parts

    try:
        header = json_decode(
            url_decode(encoded_header)
        )

        payload = json_decode(
            url_decode(encoded_payload)
        )

    except Exception:
        raise InvalidTokenError(
            "JWT Invalid"
        )

    alg = header.get("alg")

    if alg not in algorithm:
        raise JWTError(
            "Algoritma tidak disupport"
        )

    if "algs" in options:
        if alg not in options["algs"]:
            raise JWTError(
                "Algoritma tidak diperbolehkan"
            )

    config = algorithm[alg]

    header_payload = (f"{encoded_header}.{encoded_payload}").encode()

    signature = url_decode(encoded_signature)

    key = ECC.import_key(publicKey)

    hash_obj = config["hash"].new(header_payload)

    verifier = DSS.new(
        key,
        'fips-186-3'
    )

    try:
        verifier.verify(
            hash_obj,
            signature
        )

    except ValueError:
        raise InvalidSignError(
            "Signature Invalid"
        )

    now = int(time.time())

    if not options.get("ignoreExp", False):

        if "exp" in payload:

            if now >= payload["exp"]:
                raise ExpiredSignError(
                    "Token expired"
                )

    if not options.get("ignoreNbf", False):

        if "nbf" in payload:

            if now < payload["nbf"]:
                raise JWTError(
                    "Token belum aktif"
                )

    if "iss" in options:

        if payload.get("iss") != options["iss"]:
            raise JWTError(
                "iss Invalid"
            )

    if "sub" in options:

        if payload.get("sub") != options["sub"]:
            raise JWTError(
                "sub Invalid"
            )

    if "aud" in options:

        if payload.get("aud") != options["aud"]:
            raise JWTError(
                "aud Invalid"
            )

    if "jti" in options:

        if payload.get("jti") != options["jti"]:
            raise JWTError(
                "jti invalid"
            )

    return {
        "header": header,
        "payload": payload,
        "signature": encoded_signature
    }


if __name__ == "__main__":
    private_key = ECC.generate(
        curve='P-256'
    )

    public_key = private_key.public_key()

    pem_private = private_key.export_key(
        format='PEM'
    )

    pem_public = public_key.export_key(
        format='PEM'
    )

    token = sign(

        header={
            "alg": "ES256",
            "typ": "JWT"
        },

        claims={
            "iss": "Evan Raja Kripto",
            "sub": "Rafli",
            "aud": "chat",
            "iat": int(time.time()),
            "nbf": int(time.time()),
            "exp": int(time.time()) + 3600,
        },

        payload={
            "role": "admin"
        },

        privKey=pem_private
    )

    print("JWT:")
    print(token)

    decoded = verify(

    jwt=token,

    publicKey=pem_public,

    options={
        "algs": ["ES256"],
        "iss": "Evan Raja Kripto",
        "aud": "chat"
    }
)

    print("DECODED:")
    print(json.dumps(decoded))


