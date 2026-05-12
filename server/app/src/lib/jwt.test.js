import { describe, test, expect, beforeAll } from "vitest";
import * as crypto from "crypto";

import {
    sign,
    verify,
    JWTError,
    InvalidTokenError,
    InvalidSignError,
    ExpiredSignError
} from "./jwt.js";


let pemPrivate;
let pemPublic;

let wrongPemPublic;


beforeAll(() => {
    // Keypair Bener

    const {
        privateKey,
        publicKey
    } = crypto.generateKeyPairSync("ec", {
        namedCurve: "prime256v1"
    });

    pemPrivate = privateKey.export({
        type: "pkcs8",
        format: "pem"
    });

    pemPublic = publicKey.export({
        type: "spki",
        format: "pem"
    });

    // Keypair Salah

    const {
        publicKey: wrongPublicKey
    } = crypto.generateKeyPairSync("ec", {
        namedCurve: "prime256v1"
    });

    wrongPemPublic = wrongPublicKey.export({
        type: "spki",
        format: "pem"
    });
});

// Happy Path Test

describe("Happy Path Tests", () => {

    test("JWT berhasil di sign", () => {

        const token = sign(
            {
                alg: "ES256",
                typ: "JWT"
            },
            {
                iss: "server",
                sub: "user123",
                aud: "chat",
                exp: Math.floor(Date.now() / 1000) + 3600
            },
            {
                role: "admin"
            },
            pemPrivate
        );

        expect(typeof token).toBe("string");

        expect(token.split(".").length)
            .toBe(3);
    });


    test("Verify JWT berhasil", () => {

        const token = sign(
            {
                alg: "ES256",
                typ: "JWT"
            },
            {
                iss: "server",
                sub: "user123",
                aud: "chat",
                exp: Math.floor(Date.now() / 1000) + 3600
            },
            {
                role: "admin"
            },
            pemPrivate
        );

        const decoded = verify(
            token,
            pemPublic,
            {
                algs: ["ES256"],
                iss: "server",
                aud: "chat"
            }
        );

        expect(decoded.payload.role)
            .toBe("admin");

        expect(decoded.payload.sub)
            .toBe("user123");
    });
});

// Edge Case Sign

describe("Edge Case sign", () => {

    test("Gaada alg", () => {

        expect(() => {
            sign(
                {
                    typ: "JWT"
                },
                {},
                {},
                pemPrivate
            );
        }).toThrow(JWTError);
    });


    test("Algoritma gak support", () => {

        expect(() => {
            sign(
                {
                    alg: "HS256",
                    typ: "JWT"
                },
                {},
                {},
                pemPrivate
            );
        }).toThrow(JWTError);
    });


    test("typ nya salah", () => {

        expect(() => {
            sign(
                {
                    alg: "ES256",
                    typ: "JWS"
                },
                {},
                {},
                pemPrivate
            );
        }).toThrow(JWTError);
    });


    test("Parameter kelebihan", () => {

        expect(() => {
            sign(
                {
                    alg: "ES256",
                    typ: "JWT",
                    foo: "bar"
                },
                {},
                {},
                pemPrivate
            );
        }).toThrow(JWTError);
    });
});

// Edge Case Verify

describe("Edge Cases verify", () => {

    test("Signature salah", () => {

        const token = sign(
            {
                alg: "ES256",
                typ: "JWT"
            },
            {
                exp: Math.floor(Date.now() / 1000) + 3600
            },
            {
                role: "admin"
            },
            pemPrivate
        );

        expect(() => {
            verify(
                token,
                wrongPemPublic
            );
        }).toThrow(InvalidSignError);
    });


    test("Token expired", () => {

        const token = sign(
            {
                alg: "ES256",
                typ: "JWT"
            },
            {
                exp: Math.floor(Date.now() / 1000) - 10
            },
            {},
            pemPrivate
        );

        expect(() => {
            verify(
                token,
                pemPublic
            );
        }).toThrow(ExpiredSignError);
    });


    test("aud salah", () => {

        const token = sign(
            {
                alg: "ES256",
                typ: "JWT"
            },
            {
                aud: "chat-app",
                exp: Math.floor(Date.now() / 1000) + 3600
            },
            {},
            pemPrivate
        );

        expect(() => {
            verify(
                token,
                pemPublic,
                {
                    aud: "other-app"
                }
            );
        }).toThrow(JWTError);
    });
});