import { describe, it, expect } from "bun:test";
import * as jose from "jose";
import { SDPacker } from "../core/src/issuer";
import { SDJwt } from "../core/src/sdJwt";
import { Verifier } from "../core/src/verifier";
import { digest } from "../core/src/common";

describe("Regression fixes", () => {
  it("resets disclosures on each top-level pack call", async () => {
    const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
    const packer = new SDPacker();

    const first = await packer.pack({ secret: "one" }, { secret: true });
    const firstDisclosure = first.disclosures[0];
    expect(firstDisclosure.key).toBe("secret");

    const second = await packer.pack({ other: "two" }, { other: true });
    const packedSecond = second.packedPayload;
    const disclosuresSecond = second.disclosures;
    expect(disclosuresSecond).toHaveLength(1);
    expect(disclosuresSecond[0].key).toBe("other");
    expect(disclosuresSecond[0].digestValue).not.toBe(firstDisclosure.digestValue);

    const jwt = await new jose.SignJWT(packedSecond)
      .setProtectedHeader({ alg: "ES256" })
      .sign(privateKey);
    const sdJwt = new SDJwt(jwt, disclosuresSecond);
    const verifier = new Verifier();
    const verified = await verifier.verify(sdJwt, publicKey);
    expect(verified.other).toBe("two");
  });

  it("hashes with SHA-224 using runtime fallback support", async () => {
    const expected = "6gmunMZ2jFD87pA-0FRVblv8g0eQfxJZiqJBkw";
    const actual = await digest("hello", "sha-224");
    expect(actual).toBe(expected);
  });

  it("enforces a default KB-JWT freshness window with an override escape hatch", async () => {
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
    const defaultMaxAge =
      (Verifier as any).defaultKbMaxAgeSeconds ?? 600;
    const staleIat = now - (defaultMaxAge + 60);
    const kbJwt = await new jose.SignJWT({
      nonce: "n",
      aud: "aud",
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
        aud: "aud",
        now,
      })
    ).rejects.toThrow("KB-JWT iat is too old");

    await verifier.verify(sdJwt, issuerKeys.publicKey, {
      required: true,
      nonce: "n",
      aud: "aud",
      now,
      kbMaxAgeSeconds: Infinity,
    });
  });
});
