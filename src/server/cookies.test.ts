import { NextResponse } from "next/server.js";
import * as jose from "jose";
import { describe, expect, it } from "vitest";

import { generateSecret } from "../test/utils.js";
import {
  addCacheControlHeadersForSession,
  decrypt,
  encrypt,
  sign,
  verifySigned
} from "./cookies.js";
import { SessionSecretConfig } from "./session/abstract-session-store.js";

describe("encrypt/decrypt", async () => {
  const secret = await generateSecret(32);
  const incorrectSecret = await generateSecret(32);

  describe("with string secret", () => {
    it("should encrypt/decrypt a payload with the correct secret", async () => {
      const payload = { key: "value" };
      const maxAge = 60 * 60; // 1 hour in seconds
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const encrypted = await encrypt(payload, secret, expiration);
      const decrypted = (await decrypt(
        encrypted,
        secret
      )) as jose.JWTDecryptResult;

      expect(decrypted!.payload).toEqual(expect.objectContaining(payload));
    });

    it("should fail to decrypt a payload with the incorrect secret", async () => {
      const payload = { key: "value" };
      const maxAge = 60 * 60; // 1 hour in seconds
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const encrypted = await encrypt(payload, secret, expiration);
      const decrypted = await decrypt(encrypted, incorrectSecret);
      expect(decrypted).toBeNull();
    });

    it("should fail to decrypt when expired", async () => {
      const payload = { key: "value" };
      const expiration = Math.floor(Date.now() / 1000 - 60); // 60 seconds in the past
      const encrypted = await encrypt(payload, secret, expiration);
      const decrypted = await decrypt(encrypted, secret);
      expect(decrypted).toBeNull();
    });

    it("should fail to decrypt a tampered payload", async () => {
      const payload = { key: "value" };
      const maxAge = 60 * 60; // 1 hour in seconds
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const encrypted = await encrypt(payload, secret, expiration);

      // Tamper with the encrypted payload by shifting the first character
      const tampered =
        String.fromCharCode(encrypted.charCodeAt(0) + 1) + encrypted.slice(1);

      const decrypted = await decrypt(tampered, secret);
      expect(decrypted).toBeNull();
    });

    it("should fail to encrypt if a secret is not provided", async () => {
      const payload = { key: "value" };
      const maxAge = 60 * 60; // 1 hour in seconds
      const expiration = Math.floor(Date.now() / 1000 + maxAge);

      await expect(() =>
        encrypt(payload, "", expiration)
      ).rejects.toThrowError();
    });

    it("should fail to decrypt if a secret is not provided", async () => {
      const payload = { key: "value" };
      const maxAge = 60 * 60; // 1 hour in seconds
      const expiration = Math.floor(Date.now() / 1000 + maxAge);

      const encrypted = await encrypt(payload, secret, expiration);
      await expect(() => decrypt(encrypted, "")).rejects.toThrowError();
    });
  });

  describe("with object secret (key rotation)", async () => {
    const currentSecret = await generateSecret(32);
    const oldSecret = await generateSecret(32);
    const objectSecret: SessionSecretConfig = {
      currentKid: "key-2",
      allowedKeys: {
        "key-1": oldSecret,
        "key-2": currentSecret
      }
    };

    it("should encrypt with the current key and include kid in header", async () => {
      const payload = { key: "value" };
      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const encrypted = await encrypt(payload, objectSecret, expiration);

      // Verify the encrypted token has the kid in the header
      const header = jose.decodeProtectedHeader(encrypted);
      expect(header.kid).toBe("key-2");
    });

    it("should encrypt/decrypt a payload with the current key", async () => {
      const payload = { key: "value" };
      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const encrypted = await encrypt(payload, objectSecret, expiration);
      const decrypted = (await decrypt(
        encrypted,
        objectSecret
      )) as jose.JWTDecryptResult;

      expect(decrypted!.payload).toEqual(expect.objectContaining(payload));
    });

    it("should decrypt payloads encrypted with an old key (key rotation)", async () => {
      const oldObjectSecret: SessionSecretConfig = {
        currentKid: "key-1",
        allowedKeys: {
          "key-1": oldSecret
        }
      };

      const payload = { key: "value" };
      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      // Encrypt with old key
      const encrypted = await encrypt(payload, oldObjectSecret, expiration);

      // Decrypt with new configuration that includes both keys
      const decrypted = (await decrypt(
        encrypted,
        objectSecret
      )) as jose.JWTDecryptResult;

      expect(decrypted!.payload).toEqual(expect.objectContaining(payload));
    });

    it("should return null when kid is not found in allowedKeys", async () => {
      const unknownKeySecret: SessionSecretConfig = {
        currentKid: "key-unknown",
        allowedKeys: {
          "key-unknown": await generateSecret(32)
        }
      };

      const payload = { key: "value" };
      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      // Encrypt with unknown key
      const encrypted = await encrypt(payload, unknownKeySecret, expiration);

      // Decrypt with object secret that doesn't have the unknown key
      const decrypted = await decrypt(encrypted, objectSecret);

      expect(decrypted).toBeNull();
    });

    it("should decrypt string-encrypted payloads (no kid) by falling back to currentKid when no fallbackKid is specified", async () => {
      // Encrypt with simple string secret (no kid in header)
      const payload = { key: "value" };
      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const encrypted = await encrypt(payload, currentSecret, expiration);

      // Verify the encrypted token has no kid
      const header = jose.decodeProtectedHeader(encrypted);
      expect(header.kid).toBeUndefined();

      // Decrypt with object secret should fall back to currentKid
      const decrypted = (await decrypt(
        encrypted,
        objectSecret
      )) as jose.JWTDecryptResult;

      expect(decrypted!.payload).toEqual(expect.objectContaining(payload));
    });

    it("should decrypt string-encrypted payloads (no kid) by falling back to fallbackKid when specified", async () => {
      // Encrypt with old secret (no kid in header)
      const payload = { key: "value" };
      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const encrypted = await encrypt(payload, oldSecret, expiration);

      // Verify the encrypted token has no kid
      const header = jose.decodeProtectedHeader(encrypted);
      expect(header.kid).toBeUndefined();

      // Object secret with fallbackKid pointing to the old key
      const objectSecretWithFallback: SessionSecretConfig = {
        currentKid: "key-2",
        fallbackKid: "key-1",
        allowedKeys: {
          "key-1": oldSecret,
          "key-2": currentSecret
        }
      };

      // Decrypt should use fallbackKid (key-1) instead of currentKid (key-2)
      const decrypted = (await decrypt(
        encrypted,
        objectSecretWithFallback
      )) as jose.JWTDecryptResult;

      expect(decrypted!.payload).toEqual(expect.objectContaining(payload));
    });

    it("should fail to decrypt string-encrypted payloads (no kid) when fallbackKid points to wrong key", async () => {
      // Encrypt with current secret (no kid in header)
      const payload = { key: "value" };
      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const encrypted = await encrypt(payload, currentSecret, expiration);

      // Object secret with fallbackKid pointing to a different key than what was used to encrypt
      const objectSecretWithWrongFallback: SessionSecretConfig = {
        currentKid: "key-2",
        fallbackKid: "key-1",
        allowedKeys: {
          "key-1": oldSecret,
          "key-2": currentSecret
        }
      };

      // Decrypt should try fallbackKid (key-1) which is wrong, so it should fail
      const decrypted = await decrypt(encrypted, objectSecretWithWrongFallback);

      expect(decrypted).toBeNull();
    });

    it("should fail to decrypt if all keys are wrong", async () => {
      const wrongKeySecret: SessionSecretConfig = {
        currentKid: "key-wrong",
        allowedKeys: {
          "key-wrong": await generateSecret(32)
        }
      };

      const payload = { key: "value" };
      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const encrypted = await encrypt(payload, objectSecret, expiration);

      const decrypted = await decrypt(encrypted, wrongKeySecret);
      expect(decrypted).toBeNull();
    });

    it("should fail to decrypt when expired", async () => {
      const payload = { key: "value" };
      const expiration = Math.floor(Date.now() / 1000 - 60); // 60 seconds in the past
      const encrypted = await encrypt(payload, objectSecret, expiration);
      const decrypted = await decrypt(encrypted, objectSecret);
      expect(decrypted).toBeNull();
    });

    it("should fail to decrypt a tampered payload", async () => {
      const payload = { key: "value" };
      const maxAge = 60 * 60; // 1 hour in seconds
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const encrypted = await encrypt(payload, objectSecret, expiration);

      // Tamper with the encrypted payload by shifting the first character
      const tampered =
        String.fromCharCode(encrypted.charCodeAt(0) + 1) + encrypted.slice(1);

      const decrypted = await decrypt(tampered, objectSecret);
      expect(decrypted).toBeNull();
    });

    it("should fail to encrypt if current key secret is empty", async () => {
      const emptyKeySecret: SessionSecretConfig = {
        currentKid: "key-1",
        allowedKeys: {
          "key-1": ""
        }
      };
      const payload = { key: "value" };
      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);

      await expect(() =>
        encrypt(payload, emptyKeySecret, expiration)
      ).rejects.toThrowError();
    });
  });
});

describe("sign/verifySigned", async () => {
  const secret = await generateSecret(32);

  describe("with string secret", () => {
    it("should sign and verify a value", async () => {
      const name = "testCookie";
      const value = "testValue";
      const signed = await sign(name, value, secret);
      const verified = await verifySigned(name, signed, secret);

      expect(verified).toBe(value);
    });

    it("should fail to verify with incorrect secret", async () => {
      const name = "testCookie";
      const value = "testValue";
      const signed = await sign(name, value, secret);
      const incorrectSecret = await generateSecret(32);

      const verified = await verifySigned(name, signed, incorrectSecret);
      expect(verified).toBeUndefined();
    });

    it("should fail to verify with incorrect name", async () => {
      const name = "testCookie";
      const value = "testValue";
      const signed = await sign(name, value, secret);

      const verified = await verifySigned("wrongName", signed, secret);
      expect(verified).toBeUndefined();
    });

    it("should return undefined for empty value", async () => {
      const verified = await verifySigned("name", "", secret);
      expect(verified).toBeUndefined();
    });
  });

  describe("with object secret", async () => {
    // Note: sign/verifySigned are legacy migration functions.
    // Key rotation via kid headers is not supported because the protected header is not preserved.
    // When verifying, fallbackKid (if specified) or currentKid is used.
    const currentSecret = await generateSecret(32);
    const oldSecret = await generateSecret(32);
    const objectSecret: SessionSecretConfig = {
      currentKid: "key-1",
      allowedKeys: {
        "key-1": currentSecret
      }
    };

    it("should verify string-signed values using currentKid when no fallbackKid is specified", async () => {
      const name = "testCookie";
      const value = "testValue";
      // Sign with simple string secret
      const signed = await sign(name, value, currentSecret);

      // Verify with object secret should use currentKid
      const verified = await verifySigned(name, signed, objectSecret);

      expect(verified).toBe(value);
    });

    it("should verify string-signed values using fallbackKid when specified", async () => {
      const name = "testCookie";
      const value = "testValue";
      // Sign with old secret
      const signed = await sign(name, value, oldSecret);

      const objectSecretWithFallback: SessionSecretConfig = {
        currentKid: "key-2",
        fallbackKid: "key-1",
        allowedKeys: {
          "key-1": oldSecret,
          "key-2": currentSecret
        }
      };

      // Verify with object secret should use fallbackKid (key-1)
      const verified = await verifySigned(
        name,
        signed,
        objectSecretWithFallback
      );

      expect(verified).toBe(value);
    });

    it("should fail to verify string-signed values when fallbackKid points to wrong key", async () => {
      const name = "testCookie";
      const value = "testValue";
      // Sign with current secret
      const signed = await sign(name, value, currentSecret);

      const objectSecretWithWrongFallback: SessionSecretConfig = {
        currentKid: "key-2",
        fallbackKid: "key-1",
        allowedKeys: {
          "key-1": oldSecret,
          "key-2": currentSecret
        }
      };

      // Verify should try fallbackKid (key-1) which is wrong, so it should fail
      const verified = await verifySigned(
        name,
        signed,
        objectSecretWithWrongFallback
      );

      expect(verified).toBeUndefined();
    });
  });
});

describe("addCacheControlHeadersForSession", () => {
  it("unconditionally adds strict cache headers", () => {
    const res = NextResponse.next();

    addCacheControlHeadersForSession(res);

    expect(res.headers.get("Cache-Control")).toBe(
      "private, no-cache, no-store, must-revalidate, max-age=0"
    );
    expect(res.headers.get("Pragma")).toBe("no-cache");
    expect(res.headers.get("Expires")).toBe("0");
  });
});
