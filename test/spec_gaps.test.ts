import { describe, it, expect, beforeAll } from "bun:test";
import * as jose from "jose";
import { SDPacker } from "../src/issuer";
import { SDJwt } from "../src/sdJwt";
import { Verifier } from "../src/verifier";

// Regression coverage for scenarios that previously slipped through the implementation.
describe("Spec gaps – regression coverage", () => {
  let issuerPriv: jose.KeyLike;
  let issuerPub: jose.KeyLike;

  beforeAll(async () => {
    const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
    issuerPriv = privateKey;
    issuerPub = publicKey;
  });

  it("should reject SD-JWTs that omit validity-controlling claims (exp/nbf)", async () => {
    // No exp/nbf present; spec requires the verifier to reject when required
    const payload = { sub: "user-without-validity" };
    const packer = new SDPacker();
    const { packedPayload, disclosures } = await packer.pack(payload, {});
    const jwt = await new jose.SignJWT(packedPayload)
      .setProtectedHeader({ alg: "ES256" })
      .sign(issuerPriv);
    const sdJwt = new SDJwt(jwt, disclosures);
    const verifier = new Verifier();

    await expect(verifier.verify(sdJwt, issuerPub, { requireValidityClaims: true })).rejects.toThrow();
  });

  it("should reject Key Binding JWTs with stale iat (older than freshness window)", async () => {
    // Holder keys
    const holderKeys = await jose.generateKeyPair("ES256");
    const holderJwk = await jose.exportJWK(holderKeys.publicKey);

    // Issuer payload with cnf
    const payload = { cnf: { jwk: holderJwk }, claim: "x" };
    const packer = new SDPacker();
    const { packedPayload, disclosures } = await packer.pack(payload, {});
    const jwt = await new jose.SignJWT(packedPayload)
      .setProtectedHeader({ alg: "ES256" })
      .sign(issuerPriv);
    const sdJwt = new SDJwt(jwt, disclosures);

    // KB-JWT with iat far in the past should be rejected
    const kbJwt = await new jose.SignJWT({
      nonce: "nonce",
      aud: "aud",
      iat: Math.floor(Date.now() / 1000) - 3 * 24 * 3600, // 3 days old
      sd_hash: await sdJwt.calculateSdHash(),
    })
      .setProtectedHeader({ alg: "ES256", typ: "kb+jwt" })
      .sign(holderKeys.privateKey);

    sdJwt.kbJwt = kbJwt;

    const verifier = new Verifier();
    await expect(
      verifier.verify(sdJwt, issuerPub, {
        required: true,
        nonce: "nonce",
        aud: "aud",
        kbMaxAgeSeconds: 24 * 3600,
      })
    ).rejects.toThrow();
  });

  it("should reject Key Binding JWTs with stale iat even when KB is optional but present", async () => {
    const holderKeys = await jose.generateKeyPair("ES256");
    const holderJwk = await jose.exportJWK(holderKeys.publicKey);

    const payload = { cnf: { jwk: holderJwk }, claim: "x" };
    const packer = new SDPacker();
    const { packedPayload, disclosures } = await packer.pack(payload, {});
    const jwt = await new jose.SignJWT(packedPayload)
      .setProtectedHeader({ alg: "ES256" })
      .sign(issuerPriv);
    const sdJwt = new SDJwt(jwt, disclosures);

    const kbJwt = await new jose.SignJWT({
      nonce: "nonce",
      aud: "aud",
      iat: Math.floor(Date.now() / 1000) - 3 * 24 * 3600, // 3 days old
      sd_hash: await sdJwt.calculateSdHash(),
    })
      .setProtectedHeader({ alg: "ES256", typ: "kb+jwt" })
      .sign(holderKeys.privateKey);

    sdJwt.kbJwt = kbJwt;
  const verifier = new Verifier();

  // No kbOptions provided (KB treated as optional)
  await expect(
    verifier.verify(sdJwt, issuerPub, { kbMaxAgeSeconds: 24 * 3600 })
  ).rejects.toThrow();
});

  it("should reject nested use of _sd_alg (control claim must be top-level only)", async () => {
    const payload = {
      visible: "ok",
      nested: {
        _sd_alg: "sha-256", // invalid placement per spec
        secret: "x",
      },
    };

    const jwt = await new jose.SignJWT(payload)
      .setProtectedHeader({ alg: "ES256" })
      .sign(issuerPriv);
    const sdJwt = new SDJwt(jwt, []);
    const verifier = new Verifier();

    await expect(verifier.verify(sdJwt, issuerPub)).rejects.toThrow();
  });
});
