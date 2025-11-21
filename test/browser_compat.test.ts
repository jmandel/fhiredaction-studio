import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import * as jose from "jose";
import { base64UrlEncode, base64UrlDecode } from "../src/common";
import { SDPacker } from "../src/issuer";
import { SDJwt } from "../src/sdJwt";
import { Verifier } from "../src/verifier";

describe("Browser compatibility and UTF-8 safety", () => {
  let pubKey: jose.KeyLike;
  let privKey: jose.KeyLike;
  let originalBuffer: any;

  beforeAll(async () => {
    const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
    pubKey = publicKey;
    privKey = privateKey;
  });

  it("base64url helpers round-trip non-ASCII strings via UTF-8 bytes", () => {
    const value = "Möbius π漢字";
    const encoded = base64UrlEncode(value);
    const decoded = new TextDecoder().decode(base64UrlDecode(encoded));
    expect(decoded).toBe(value);
  });

  it("verifies an SD-JWT with non-ASCII claims when Buffer is unavailable", async () => {
    // Simulate browser environment without Buffer
    originalBuffer = (globalThis as any).Buffer;
    (globalThis as any).Buffer = undefined;

    const payload = { name: "Möbius π漢字" };
    const packer = new SDPacker();
    const { packedPayload, disclosures } = await packer.pack(payload, { name: true });
    const jwt = await new jose.SignJWT(packedPayload)
      .setProtectedHeader({ alg: "ES256" })
      .sign(privKey);

    const sdJwt = new SDJwt(jwt, disclosures);
    const verifier = new Verifier();
    const verified = await verifier.verify(sdJwt, pubKey);

    expect(verified.name).toBe(payload.name);
  });

  afterAll(() => {
    (globalThis as any).Buffer = originalBuffer;
  });
});
