import { describe, it, expect, beforeAll } from "bun:test";
import * as jose from "jose";
import { SDPacker } from "../src/issuer";
import { SDJwt } from "../src/sdJwt";
import { Verifier } from "../src/verifier";

describe("Spec conformance coverage", () => {
  let issuerPriv: jose.KeyLike;
  let issuerPub: jose.KeyLike;

  beforeAll(async () => {
    const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
    issuerPriv = privateKey;
    issuerPub = publicKey;
  });

  it("strips control claims (_sd_alg) from reconstructed payload", async () => {
    const payload = { visible: "yes", secret: "hidden" };
    const packer = new SDPacker();
    const { packedPayload, disclosures } = await packer.pack(payload, { secret: true });
    const jwt = await new jose.SignJWT(packedPayload)
      .setProtectedHeader({ alg: "ES256" })
      .sign(issuerPriv);
    const sdJwt = new SDJwt(jwt, disclosures);
    const verifier = new Verifier();
    const result = await verifier.verify(sdJwt, issuerPub);
    expect(result._sd_alg).toBeUndefined();
    expect(result._sd).toBeUndefined();
    expect(result.secret).toBe("hidden");
  });

  it("accepts KB-JWT signed with holder alg other than ES256 and enforces iat freshness", async () => {
    // Holder key using ES384
    const holderKeys = await jose.generateKeyPair("ES384");
    const holderJwk = await jose.exportJWK(holderKeys.publicKey);

    // Issuer payload carries cnf
    const payload = { cnf: { jwk: holderJwk }, claim: "value" };
    const packer = new SDPacker();
    const { packedPayload, disclosures } = await packer.pack(payload, {});
    const jwt = await new jose.SignJWT(packedPayload)
      .setProtectedHeader({ alg: "ES256" })
      .sign(issuerPriv);
    const sdJwt = new SDJwt(jwt, disclosures);

    // KB-JWT with ES384 and stale/future iat should be rejected
    const futureIat = Math.floor(Date.now() / 1000) + 24 * 3600;
    const badKb = await new jose.SignJWT({
      nonce: "n",
      aud: "v",
      iat: futureIat,
      sd_hash: await sdJwt.calculateSdHash(),
    })
      .setProtectedHeader({ alg: "ES384", typ: "kb+jwt" })
      .sign(holderKeys.privateKey);
    sdJwt.kbJwt = badKb;

    const verifier = new Verifier();
    await expect(
      verifier.verify(sdJwt, issuerPub, { required: true, nonce: "n", aud: "v" })
    ).rejects.toThrow();

    // Fresh iat succeeds
    const freshKb = await new jose.SignJWT({
      nonce: "n",
      aud: "v",
      iat: Math.floor(Date.now() / 1000),
      sd_hash: await sdJwt.calculateSdHash(),
    })
      .setProtectedHeader({ alg: "ES384", typ: "kb+jwt" })
      .sign(holderKeys.privateKey);
    sdJwt.kbJwt = freshKb;
    await verifier.verify(sdJwt, issuerPub, { required: true, nonce: "n", aud: "v" });
  });
});
