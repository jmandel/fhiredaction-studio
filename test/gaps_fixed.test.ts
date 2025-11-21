import { describe, it, expect } from "bun:test";
import * as jose from "jose";
import { SDPacker } from "../src/issuer";
import { SDJwt } from "../src/sdJwt";
import { Verifier } from "../src/verifier";

describe("Spec gap regressions", () => {
  it("supports recursive disclosures inside concealed array elements", async () => {
    const { publicKey, privateKey } = await jose.generateKeyPair("ES256");

    const payload = { items: [{ secret: "s", visible: "v" }] };
    const config = { items: [{ _self: true, secret: true }] };

    const packer = new SDPacker();
    const { packedPayload, disclosures } = await packer.pack(payload, config);
    const jwt = await new jose.SignJWT(packedPayload)
      .setProtectedHeader({ alg: "ES256" })
      .sign(privateKey);

    const sdJwt = new SDJwt(jwt, disclosures);
    const verifier = new Verifier();
    const verified = await verifier.verify(sdJwt, publicKey);

    expect(verified.items).toHaveLength(1);
    expect(verified.items[0].secret).toBe("s");
    expect(verified.items[0].visible).toBe("v");
  });

  it("allows as-of time when validating exp/nbf", async () => {
    const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
    const now = Math.floor(Date.now() / 1000);
    const payload = { exp: now - 10, nbf: now - 100 };

    const packer = new SDPacker();
    const { packedPayload, disclosures } = await packer.pack(payload, {});
    const jwt = await new jose.SignJWT(packedPayload)
      .setProtectedHeader({ alg: "ES256" })
      .sign(privateKey);
    const sdJwt = new SDJwt(jwt, disclosures);
    const verifier = new Verifier();

    await expect(
      verifier.verify(sdJwt, publicKey, { requireValidityClaims: true })
    ).rejects.toThrow();

    await verifier.verify(sdJwt, publicKey, {
      requireValidityClaims: true,
      now: now - 50,
    });
  });

  it("treats KB-JWT staleness as policy-driven and honors an as-of moment", async () => {
    const issuerKeys = await jose.generateKeyPair("ES256");
    const holderKeys = await jose.generateKeyPair("ES256");
    const holderJwk = await jose.exportJWK(holderKeys.publicKey);

    const payload = { cnf: { jwk: holderJwk } };
    const packer = new SDPacker();
    const { packedPayload, disclosures } = await packer.pack(payload, {});
    const jwt = await new jose.SignJWT(packedPayload)
      .setProtectedHeader({ alg: "ES256" })
      .sign(issuerKeys.privateKey);
    const sdJwt = new SDJwt(jwt, disclosures);

    const now = Math.floor(Date.now() / 1000);
    const staleIat = now - 3 * 24 * 3600; // 3 days old
    const kbJwt = await new jose.SignJWT({
      nonce: "n",
      aud: "v",
      iat: staleIat,
      sd_hash: await sdJwt.calculateSdHash(),
    })
      .setProtectedHeader({ alg: "ES256", typ: "kb+jwt" })
      .sign(holderKeys.privateKey);
    sdJwt.kbJwt = kbJwt;

    const verifier = new Verifier();

    await expect(
      verifier.verify(sdJwt, issuerKeys.publicKey, {
        required: true,
        nonce: "n",
        aud: "v",
        now,
      })
    ).rejects.toThrow("KB-JWT iat is too old");

    await verifier.verify(sdJwt, issuerKeys.publicKey, {
      required: true,
      nonce: "n",
      aud: "v",
      now,
      kbMaxAgeSeconds: Infinity,
    });

    await expect(
      verifier.verify(sdJwt, issuerKeys.publicKey, {
        required: true,
        nonce: "n",
        aud: "v",
        now,
        kbMaxAgeSeconds: 3600, // too old under this policy
      })
    ).rejects.toThrow("KB-JWT iat is too old");
  });

  it("accepts RSA holder keys for KB-JWT verification", async () => {
    const issuerKeys = await jose.generateKeyPair("ES256");
    const holderKeys = await jose.generateKeyPair("RS256");
    const holderJwk = await jose.exportJWK(holderKeys.publicKey);

    const payload = { cnf: { jwk: holderJwk }, claim: "value" };
    const packer = new SDPacker();
    const { packedPayload, disclosures } = await packer.pack(payload, {});
    const jwt = await new jose.SignJWT(packedPayload)
      .setProtectedHeader({ alg: "ES256" })
      .sign(issuerKeys.privateKey);
    const sdJwt = new SDJwt(jwt, disclosures);

    const kbJwt = await new jose.SignJWT({
      nonce: "n",
      aud: "v",
      iat: Math.floor(Date.now() / 1000),
      sd_hash: await sdJwt.calculateSdHash(),
    })
      .setProtectedHeader({ alg: "RS256", typ: "kb+jwt" })
      .sign(holderKeys.privateKey);
    sdJwt.kbJwt = kbJwt;

    const verifier = new Verifier();
    const verified = await verifier.verify(sdJwt, issuerKeys.publicKey, {
      required: true,
      nonce: "n",
      aud: "v",
    });
    expect(verified.claim).toBe("value");
  });

  it("supports sha-1 normalization for hashing disclosures", async () => {
    const issuerKeys = await jose.generateKeyPair("ES256");
    const payload = { secret: "x" };
    const config = { secret: true };

    const packer = new SDPacker(undefined, "SHA-1");
    const { packedPayload, disclosures } = await packer.pack(payload, config);

    const jwt = await new jose.SignJWT(packedPayload)
      .setProtectedHeader({ alg: "ES256" })
      .sign(issuerKeys.privateKey);

    const sdJwt = new SDJwt(jwt, disclosures);
    const verifier = new Verifier();
    const verified = await verifier.verify(sdJwt, issuerKeys.publicKey);
    expect(verified.secret).toBe("x");
  });

  it("throws when using SDJwt.getClaims (unsafe helper)", async () => {
    const sdJwt = new SDJwt("placeholder", []);
    await expect(sdJwt.getClaims(new Uint8Array())).rejects.toThrow(
      "deprecated"
    );
  });
});
