# sd-jwt-bun

Selective Disclosure JWT (SD-JWT) toolkit for Bun/TypeScript. Implements RFC 9901 concepts with a practical API for issuers, holders, and verifiers, plus optional FHIR helpers.

## Installation

```
bun add sd-jwt-bun
```

## Quick start

```ts
import * as jose from "jose";
import { SDPacker, SDJwt, Verifier } from "sd-jwt-bun";

// Issuer side: pack and sign
const payload = { name: "Alice", email: "alice@example.com" };
const config = { email: true }; // email is selectively disclosable

const packer = new SDPacker();
const { packedPayload, disclosures } = await packer.pack(payload, config);

const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
const jwt = await new jose.SignJWT(packedPayload)
  .setProtectedHeader({ alg: "ES256" })
  .sign(privateKey);

// Holder sends SD-JWT string (with a trailing "~" when no KB-JWT)
const sdJwt = new SDJwt(jwt, disclosures);
const sdJwtString = sdJwt.toString();

// Verifier side
const parsed = await SDJwt.parse(sdJwtString);
const verifier = new Verifier();
const claims = await verifier.verify(parsed, publicKey, {
  // optional KB-JWT policy:
  required: false,
  nonce: "nonce-here",
  aud: "https://verifier.example",
  // freshness: defaults to 10 minutes; override with kbMaxAgeSeconds if needed
});
console.log(claims.email); // only present if disclosed
```

### Key Binding (holder-bound presentations)

To bind an SD-JWT to a holder key and prevent replay:

1. **Issuer** includes the holder public key in the SD-JWT payload:
   ```json
   { "cnf": { "jwk": <holder public JWK> }, ... }
   ```
2. **Holder** computes `sd_hash` for the presentation:
   ```ts
   const sdHash = await sdJwt.calculateSdHash(); // uses _sd_alg or SHA-256 default
   ```
3. **Holder** creates a KB-JWT with header `{ alg: "<holder alg>", typ: "kb+jwt" }` and payload:
   ```json
   { "nonce": "<verifier nonce>", "aud": "<verifier id>", "iat": <epoch seconds>, "sd_hash": "<hash from step 2>" }
   ```
   and signs it with the holder private key. Attach it with `sdJwt.kbJwt = signedKbJwt`.
4. **Verifier** enforces binding:
   ```ts
   await verifier.verify(sdJwt, issuerPubKey, {
     required: true,
     nonce: "<same nonce>",
     aud: "<same aud>",
     kbMaxAgeSeconds: 600, // default; override if your policy differs
   });
   ```
   It checks `typ`, alg/key compatibility, `sd_hash`, `nonce`, `aud`, and `iat` freshness. Missing/incorrect values are rejected.

## API surface

### `SDPacker`

```ts
const packer = new SDPacker(saltGenerator?, hashAlg?);
const { packedPayload, disclosures } = await packer.pack(payload, config);
```

- `payload`: any JSON-like value.
- `config`: mirrors the payload shape; `true` means conceal; objects/arrays may include `_self`, `_items`, and `_decoys` keys to hide the container or add decoys.
- `hashAlg`: defaults to `SHA-256`; supports other registry algorithms (e.g., `SHA-512/256`, `SHA-224`, `SHA3-256`).
- Stateless: each call returns its own `disclosures` array; no retained internal state.

### `SDJwt`

- `new SDJwt(jwt, disclosures, kbJwt?)`: hold the issuer-signed JWT, selected disclosures, and optional KB-JWT.
- `toString(includeKbJwt = true)`: compact SD-JWT or SD-JWT+KB string.
- `calculateSdHash(alg?)`: compute `sd_hash` for KB-JWT binding (default `SHA-256`).
- `static parse(str)`: async parse SD-JWT or SD-JWT+KB string into an `SDJwt` instance.

### `Verifier`

```ts
const verifier = new Verifier();
const claims = await verifier.verify(sdJwt, issuerPubKey, {
  required?: boolean,          // require KB-JWT (default false)
  nonce?: string,              // required if KB-JWT is present
  aud?: string,                // required if KB-JWT is present
  now?: number,                // epoch seconds override for testing
  kbMaxAgeSeconds?: number,    // default 600s (10 minutes)
  kbSkewSeconds?: number,      // default 300s (5 minutes)
  requireValidityClaims?: boolean, // enforce exp/nbf presence
});
```

- Enforces duplicate digest protections, claim name collisions, correct disclosure shape (array vs object), and default KB-JWT freshness (10 minutes) unless overridden.

### Hashing helpers

- `normalizeHashAlgorithm` maps common spellings to WebCrypto names.
- `digest(data, alg?)` computes base64url digests over US-ASCII bytes of the input; falls back to Node `crypto` for algorithms missing in WebCrypto.

### FHIR helpers

`packFhirSdJwt(payload, signingKey, opts?)` builds a config from a generated FHIR index and packs/signs a resource. `verifyFhirSdJwt(sdJwtString, pubKey)` verifies it. See `fhir/src/autoSdJwt.ts`.

## Testing

```
bun test
```

Comprehensive unit tests cover packer statelessness, hash algorithm support, verifier correctness, KB-JWT freshness, and FHIR helper paths.
