import { describe, it, expect } from "bun:test";
import * as jose from "jose";
import { normalizeHashAlgorithm } from "../core/src/common";
import { Disclosure } from "../core/src/disclosure";
import { SDPacker } from "../core/src/issuer";
import { SDJwt } from "../core/src/sdJwt";
import { Verifier } from "../core/src/verifier";

describe("Reference implementation regressions", () => {
  it("fails to parse disclosures with invalid base64", async () => {
    await expect(Disclosure.parse("!!!")).rejects.toThrow(/Invalid base64 input/);
  });

  it("keeps sha-512/256 distinct from sha-512 when normalizing", () => {
    expect(normalizeHashAlgorithm("sha-512/256")).toBe("SHA-512/256");
  });

  it("rejects SD-JWT strings missing the required trailing separator", async () => {
    const issuerKeys = await jose.generateKeyPair("ES256");
    const packer = new SDPacker();
    const { packedPayload, disclosures } = await packer.pack(
      { foo: "bar" },
      { foo: true },
    );
    const jwt = await new jose.SignJWT(packedPayload)
      .setProtectedHeader({ alg: "ES256" })
      .sign(issuerKeys.privateKey);

    const sdJwt = new SDJwt(jwt, disclosures);
    const malformed = sdJwt.toString().slice(0, -1); // drop the required trailing '~'

    await expect(SDJwt.parse(malformed)).rejects.toThrow(
      "Invalid SD-JWT format: final component must be a JWT when present"
    );
  });

  it("accepts KB-JWTs signed with RSA algorithms other than RS256 when key-compatible", async () => {
    const issuerKeys = await jose.generateKeyPair("ES256");
    const holderKeys = await jose.generateKeyPair("RS512");
    const holderJwk = await jose.exportJWK(holderKeys.publicKey);

    const packer = new SDPacker();
    const { packedPayload, disclosures } = await packer.pack(
      { cnf: { jwk: holderJwk } },
      {},
    );
    const jwt = await new jose.SignJWT(packedPayload)
      .setProtectedHeader({ alg: "ES256" })
      .sign(issuerKeys.privateKey);

    const sdJwt = new SDJwt(jwt, disclosures);
    const kbJwt = await new jose.SignJWT({
      nonce: "n",
      aud: "aud",
      iat: Math.floor(Date.now() / 1000),
      sd_hash: await sdJwt.calculateSdHash(),
    })
      .setProtectedHeader({ alg: "RS512", typ: "kb+jwt" })
      .sign(holderKeys.privateKey);

    sdJwt.kbJwt = kbJwt;
    const verifier = new Verifier();
    const verified = await verifier.verify(sdJwt, issuerKeys.publicKey, {
      required: true,
      nonce: "n",
      aud: "aud",
    });

    expect(verified.cnf).toBeDefined();
  });
});
