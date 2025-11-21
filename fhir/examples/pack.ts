/**
 * Pack a FHIR fixture into an SD-JWT and persist all artifacts needed for
 * later selective presentation and verification.
 *
 * Outputs (under fhir/out):
 *   - sdjwt_full.txt      : SD-JWT with all disclosures appended
 *   - sdjwt_base.jwt      : Issuer-signed JWT (no disclosures)
 *   - disclosures.json    : Array of disclosures with metadata
 *   - packedPayload.json  : Payload with digests/_sd
 *   - issuer-public.jwk.json
 *   - issuer-private.jwk.json (demo only; do not ship in production)
 */

import { mkdir, writeFile, readFile } from "fs/promises";
import path from "path";
import * as jose from "jose";
import { packFhirSdJwt } from "../src/autoSdJwt";

const OUT_DIR = path.resolve(process.cwd(), "fhir", "out");

async function main() {
  await mkdir(OUT_DIR, { recursive: true });

  const fixturePath = path.resolve(
    process.cwd(),
    "fhir/fixtures/observation.json",
  );
  const fixture = JSON.parse(await readFile(fixturePath, "utf8"));

  // Demo keypair (Issuer)
  const { publicKey, privateKey } = await jose.generateKeyPair("ES256", {
    extractable: true,
  });
  const publicJwk = await jose.exportJWK(publicKey);
  const privateJwk = await jose.exportJWK(privateKey);

  const { sdJwt, jwt, disclosures, packedPayload } = await packFhirSdJwt(
    fixture,
    privateKey,
  );

  // Persist artifacts
  await writeFile(path.join(OUT_DIR, "sdjwt_full.txt"), sdJwt.toString(), "utf8");
  await writeFile(path.join(OUT_DIR, "sdjwt_base.jwt"), jwt, "utf8");
  await writeFile(
    path.join(OUT_DIR, "disclosures.json"),
    JSON.stringify(
      disclosures.map((d) => ({
        encoded: d.encoded,
        digest: d.digestValue,
        key: d.key,
        value: d.value,
      })),
      null,
      2,
    ),
    "utf8",
  );
  await writeFile(
    path.join(OUT_DIR, "packedPayload.json"),
    JSON.stringify(packedPayload, null, 2),
    "utf8",
  );
  await writeFile(
    path.join(OUT_DIR, "issuer-public.jwk.json"),
    JSON.stringify(publicJwk, null, 2),
    "utf8",
  );
  await writeFile(
    path.join(OUT_DIR, "issuer-private.jwk.json"),
    JSON.stringify(privateJwk, null, 2),
    "utf8",
  );

  console.log("Wrote artifacts to fhir/out:");
  console.log(`- sdjwt_full.txt`);
  console.log(`- sdjwt_base.jwt`);
  console.log(`- disclosures.json`);
  console.log(`- packedPayload.json`);
  console.log(`- issuer-public.jwk.json`);
  console.log(`- issuer-private.jwk.json (demo only)`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
