/**
 * Present a selectively disclosed SD-JWT built from persisted artifacts.
 *
 * Inputs (from fhir/out, created by pack.ts):
 *   - sdjwt_full.txt (for convenience: we re-use base JWT)
 *   - sdjwt_base.jwt
 *   - disclosures.json
 *   - issuer-public.jwk.json
 *
 * You can choose which disclosure indices to present via CLI:
 *   bun run fhir/examples/present-and-verify.ts --indices=1,3
 * If omitted, all disclosures are presented.
 *
 * Output: reconstructed FHIR payload (verified) printed to stdout.
 */

import { readFile } from "fs/promises";
import path from "path";
import * as jose from "jose";
import { SDJwt } from "../../core/src/sdJwt";
import { Disclosure } from "../../core/src/disclosure";
import { Verifier } from "../../core/src/verifier";

const OUT_DIR = path.resolve(process.cwd(), "fhir", "out");

function parseIndices(): number[] | null {
  const arg = process.argv.find((a) => a.startsWith("--indices="));
  if (!arg) return null;
  const list = arg.replace("--indices=", "");
  return list
    .split(",")
    .map((s) => parseInt(s.trim(), 10))
    .filter((n) => !Number.isNaN(n));
}

async function main() {
  const disclosuresRaw = JSON.parse(
    await readFile(path.join(OUT_DIR, "disclosures.json"), "utf8"),
  ) as { encoded: string }[];
  const baseJwt = await readFile(path.join(OUT_DIR, "sdjwt_base.jwt"), "utf8");
  const full = await readFile(path.join(OUT_DIR, "sdjwt_full.txt"), "utf8");
  const publicJwk = JSON.parse(
    await readFile(path.join(OUT_DIR, "issuer-public.jwk.json"), "utf8"),
  );
  const pubKey = await jose.importJWK(publicJwk, "ES256");

  const selected = parseIndices();
  const disclosures = await Promise.all(
    (selected ?? disclosuresRaw.map((_, i) => i)).map(async (i) => {
    const entry = disclosuresRaw[i];
    if (!entry) throw new Error(`Disclosure index out of range: ${i + 1}`);
      return Disclosure.parse(entry.encoded);
    }),
  );

  // Build subset SD-JWT: base JWT + chosen disclosures + trailing "~"
  const subset = new SDJwt(baseJwt.trim(), disclosures);
  const serialized = subset.toString();

  console.log("Presenting SD-JWT (subset of disclosures):");
  console.log(serialized);

  const verifier = new Verifier();
  const verified = await verifier.verify(subset, pubKey);
  console.log("\nReconstructed FHIR payload:");
  console.dir(verified, { depth: null });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
