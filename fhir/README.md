# FHIR SD-JWT helpers

Contents
- `defs/` — generated FHIR R4 StructureDefinition index (paths, min/max, repeating, types).
- `.cache/` — download/extract cache for the official HL7 R4 definitions (created by the generator).
- `scripts/generate-fhir-r4-index.ts` — downloads/extracts definitions and builds the index.
- `examples/pack.ts` — pack a FHIR fixture into SD-JWT and persist artifacts for later use.
- `examples/present-and-verify.ts` — read persisted artifacts, choose which disclosures to present, verify, and reconstruct.
- `examples/pack-and-verify.ts` — end-to-end single-run demo (kept for convenience).
- `fixtures/` — sample FHIR payloads used by the demo/tests.
  - `observation.json` — input fixture.
  - `observation_chain/` — persisted artifacts showing the full chain (SD-JWT, base JWT, disclosures, packed payload, verified output, issuer public JWK).
- `tests/` — FHIR-related unit tests.

Usage

Generate index (or refresh):
```bash
bun run fhir/scripts/generate-fhir-r4-index.ts
```

Persist artifacts (pack):
```bash
bun run fhir/examples/pack.ts
```
Outputs to `fhir/out/`:
- `sdjwt_full.txt` (SD-JWT with all disclosures)
- `sdjwt_base.jwt` (Issuer-signed JWT only)
- `disclosures.json` (encoded disclosures with metadata)
- `packedPayload.json` (payload with digests)
- `issuer-public.jwk.json` (for verification)
- `issuer-private.jwk.json` (demo only)

For convenience, a captured chain from the Observation fixture is stored in `fhir/fixtures/observation_chain/` (copied from a run of `pack.ts`).

Selective presentation + verification:
```bash
# all disclosures
bun run fhir/examples/present-and-verify.ts

# choose subset by 1-based indices
bun run fhir/examples/present-and-verify.ts --indices=1,3
```
Reads artifacts from `fhir/out/`, assembles an SD-JWT with the chosen disclosures, verifies with the saved issuer public JWK, and prints the reconstructed FHIR payload.

One-shot demo (pack + verify in-memory):
```bash
bun run fhir/examples/pack-and-verify.ts
```
This will:
- Load `fhir/fixtures/observation.json`
- Generate a key pair
- Pack into an SD-JWT (concealing optional + repeating by default)
- Print packed payload, disclosures, serialized SD-JWT
- Verify and print the reconstructed pure FHIR payload

Drive the interactive demo

The public demo at `public/` can be fueled directly from the artifacts produced above. After
running the pack step, copy or symlink the files into `public/data`:

```bash
# From repo root
cp fhir/out/sdjwt_full.txt public/data/sdjwt.txt
cp fhir/out/disclosures.json public/data/disclosures.json
cp fhir/out/issuer-public.jwk.json public/data/issuer_public.jwk.json
```

Then rebuild the demo assets and serve `public/` (for example with `bun build ./public/demonstration.tsx --outdir ./public` and a static file server). The UI is agnostic to FHIR semantics; it just consumes the SD-JWT plus disclosures and lets you redact by clicking or highlighting.

Tests:
```bash
bun test
```
