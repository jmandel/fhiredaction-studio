/**
 * End-to-end demo:
 * - Load a FHIR fixture
 * - Pack into an SD-JWT (concealing optional + repeating elements by default)
 * - Serialize SD-JWT (with disclosures)
 * - Verify and reconstruct to pure FHIR JSON
 */

import { readFile } from "fs/promises";
import path from "path";
import * as jose from "jose";
import { packFhirSdJwt } from "../src/autoSdJwt";
import { SDJwt } from "../../src/sdJwt";
import { Verifier } from "../../src/verifier";

async function main() {
  const fixturePath = path.resolve(
    process.cwd(),
    "fhir/fixtures/observation.json",
  );
  const fixture = JSON.parse(await readFile(fixturePath, "utf8"));

  // Generate ephemeral key pair for demo
  const { publicKey, privateKey } = await jose.generateKeyPair("ES256");

  // Pack FHIR -> SD-JWT
  const { sdJwt, packedPayload, disclosures } = await packFhirSdJwt(
    fixture,
    privateKey,
  );

  console.log("Packed payload (with digests):");
  console.dir(packedPayload, { depth: null });
  console.log("\nDisclosures:");
  disclosures.forEach((d, i) =>
    console.log(`${i + 1}: ${d.encoded} (digest=${d.digestValue})`),
  );

  const verifier = new Verifier();
  const verified = await verifier.verify(sdJwt, publicKey);

  const serialized = sdJwt.toString();
  console.log("\nSerialized SD-JWT:");
  console.log(serialized);

  console.log("\nReconstructed FHIR payload:");
  console.dir(verified, { depth: null });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
