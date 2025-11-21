import { describe, it, expect, beforeAll } from "bun:test";
import * as jose from 'jose';
import { SDPacker } from '../core/src/issuer';
import { SDJwt, ARRAY_ELEMENT_KEY, SD_KEY } from '../core/src/sdJwt';
import { Verifier } from '../core/src/verifier';
import { Disclosure } from '../core/src/disclosure';
import { digest, base64UrlEncode } from '../core/src/common';

describe("SD-JWT Comprehensive Tests (RFC 9901)", () => {
    let keyPair: any;
    let pubKey: any;
    let privKey: any;

    beforeAll(async () => {
        keyPair = await jose.generateKeyPair('ES256');
        pubKey = keyPair.publicKey;
        privKey = keyPair.privateKey;
    });

    // Test 1: Claim Name Collision
    it("should reject SD-JWT with claim name collision", async () => {
        const payload = {
            "name": "Plaintext Name",
            "_sd": [] as string[]
        };

        // Create a disclosure for "name" that collides
        const disclosure = await Disclosure.create("Hidden Name", "name");
        payload._sd.push(disclosure.digestValue!);

        const jwt = await new jose.SignJWT(payload)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);

        const sdJwt = new SDJwt(jwt, [disclosure]);
        const verifier = new Verifier();

        expect(verifier.verify(sdJwt, pubKey)).rejects.toThrow("Claim name collision: name");
    });

    // Test 2: Duplicate Digests
    it("should reject SD-JWT with duplicate digests", async () => {
        const payload = {
            "_sd": [] as string[]
        };

        const disclosure = await Disclosure.create("value", "key");
        // Add same digest twice
        payload._sd.push(disclosure.digestValue!);
        payload._sd.push(disclosure.digestValue!);

        const jwt = await new jose.SignJWT(payload)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);

        // Only need one disclosure in the list for it to be found twice
        const sdJwt = new SDJwt(jwt, [disclosure]);
        const verifier = new Verifier();

        expect(verifier.verify(sdJwt, pubKey)).rejects.toThrow();
    });

    // Test 3: Malformed Disclosures
    it("should reject malformed disclosures", async () => {
        const payload = {
            "_sd": [] as string[]
        };
        
        // 1. Invalid JSON
        const badJson = "Not JSON";
        // We need to base64url encode it to be passed as a "valid" disclosure string format
        const encodedBadJson = base64UrlEncode(badJson); 
        // Wait, my base64urlEncode helper?
        // Use common.ts if possible, but here constructing manually.
        // `Disclosure.parse` handles decoding.
        
        // Let's try passing a disclosure that parses to something invalid
        // e.g. not an array
        const notArray = JSON.stringify({ a: 1 });
        const encodedNotArray = base64UrlEncode(notArray);
        
        await expect(Disclosure.parse(encodedNotArray)).rejects.toThrow("Disclosure must be an array");
        
        // e.g. array length 1
        const shortArray = JSON.stringify(["salt"]);
        const encodedShort = base64UrlEncode(shortArray);
        await expect(Disclosure.parse(encodedShort)).rejects.toThrow("Disclosure array must have 2 or 3 elements");
    });

    // Test 4: Key Binding Validation
    it("should validate Key Binding JWT thoroughly", async () => {
        const payload = {
            sub: "holder",
            cnf: {
                jwk: await jose.exportJWK(pubKey)
            }
        };
        
        const packer = new SDPacker();
        const { packedPayload, disclosures } = await packer.pack(payload, {});
        
        const jwt = await new jose.SignJWT(packedPayload)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);
            
        const sdJwt = new SDJwt(jwt, disclosures);
        const sdHash = await sdJwt.calculateSdHash();
        
        const verifier = new Verifier();

        // 1. Test sd_hash mismatch
        const badKbJwt = await new jose.SignJWT({
            nonce: "123",
            aud: "verifier",
            iat: Math.floor(Date.now() / 1000),
            sd_hash: "bad_hash"
        })
        .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
        .sign(privKey);
        
        sdJwt.kbJwt = badKbJwt;
        await expect(verifier.verify(sdJwt, pubKey, { required: true })).rejects.toThrow("sd_hash mismatch");

        // 2. Test nonce mismatch
        const correctKbJwt = await new jose.SignJWT({
            nonce: "123",
            aud: "verifier",
            iat: Math.floor(Date.now() / 1000),
            sd_hash: sdHash
        })
        .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
        .sign(privKey);
        
        sdJwt.kbJwt = correctKbJwt;
        
        // Should pass with correct nonce
        await verifier.verify(sdJwt, pubKey, { required: true, nonce: "123" });
        
        // Fail with incorrect expected nonce
        await expect(verifier.verify(sdJwt, pubKey, { required: true, nonce: "999" })).rejects.toThrow("KB-JWT nonce mismatch");

        // 3. Test invalid typ
        const invalidTypKbJwt = await new jose.SignJWT({
            nonce: "123",
            aud: "verifier",
            iat: Math.floor(Date.now() / 1000),
            sd_hash: sdHash
        })
        .setProtectedHeader({ alg: 'ES256', typ: 'jwt' }) // Not kb+jwt
        .sign(privKey);
        
        sdJwt.kbJwt = invalidTypKbJwt;
        await expect(verifier.verify(sdJwt, pubKey, { required: true })).rejects.toThrow("Key Binding JWT must have typ 'kb+jwt'");
    });

    // Test 5: Alternative Hash Algorithm
    it("should support SHA-512 via _sd_alg", async () => {
        const payload = {
            secret: "super secret"
        };
        const config = { secret: true };
        
        // Pass SHA-512 to packer
        const packer = new SDPacker(undefined, 'SHA-512');
        const { packedPayload, disclosures } = await packer.pack(payload, config);
        
        packedPayload._sd_alg = 'SHA-512';
        
        const jwt = await new jose.SignJWT(packedPayload)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);
            
        const sdJwt = new SDJwt(jwt, disclosures);
        
        // Verify disclosures use SHA-512 digests
        const d = disclosures[0];
        await d.calculateDigest('SHA-512');
        expect(packedPayload._sd).toContain(d.digestValue!);
        
        // Verify with verifier
        const verifier = new Verifier();
        const result = await verifier.verify(sdJwt, pubKey);
        expect(result.secret).toBe("super secret");
    });
    
    // Test 6: Orphaned Disclosures (Child without Parent)
    it("should detect unused disclosures when parent is missing", async () => {
        const payload = {
            parent: {
                child: "value"
            }
        };
        
        // Conceal parent AND child
        const config = {
            parent: {
                _self: true,
                child: true
            }
        };
        
        const packer = new SDPacker();
        const { packedPayload, disclosures } = await packer.pack(payload, config);
        // disclosures[0] is child (created first in recursion), disclosures[1] is parent.
        // Let's verify this assumption.
        const childDisclosure = disclosures.find(d => d.key === 'child');
        const parentDisclosure = disclosures.find(d => d.key === 'parent');
        
        if (!childDisclosure || !parentDisclosure) throw new Error("Setup failed");
        
        // Construct SD-JWT with child but WITHOUT parent
        // The parent digest is in the payload. But we don't provide the parent disclosure.
        // But we DO provide the child disclosure.
        // The child disclosure's digest is inside the parent's value.
        // Since parent is not disclosed, the Verifier never sees the child's digest.
        // Thus child disclosure is unused.
        
        const jwt = await new jose.SignJWT(packedPayload)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);
            
        const sdJwt = new SDJwt(jwt, [childDisclosure]); // Only child
        
        const verifier = new Verifier();
        
        await expect(verifier.verify(sdJwt, pubKey)).rejects.toThrow("Unused disclosures found");
    });

    // Test 7: Incorrect Disclosure Type
    it("should reject if disclosure type does not match usage context", async () => {
        const payload = {
            array: ["A"],
            obj: { a: 1 },
            "_sd": [] as string[]
        };
        
        // Case 1: Array disclosure (2-element) used in Object context
        const arrayDisclosure = await Disclosure.create("value", undefined, "salt1"); // No key
        payload._sd.push(arrayDisclosure.digestValue!);
        
        const jwt1 = await new jose.SignJWT(payload)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);
            
        const sdJwt1 = new SDJwt(jwt1, [arrayDisclosure]);
        const verifier = new Verifier();
        
        await expect(verifier.verify(sdJwt1, pubKey)).rejects.toThrow("Disclosure for object property must have a key");
        
        // Case 2: Object disclosure (3-element) used in Array context
        const objDisclosure = await Disclosure.create("value", "key", "salt2");
        const arrayPayload = {
            array: [{ "...": objDisclosure.digestValue }]
        };
        
        const jwt2 = await new jose.SignJWT(arrayPayload)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);
            
        const sdJwt2 = new SDJwt(jwt2, [objDisclosure]);
        
        await expect(verifier.verify(sdJwt2, pubKey)).rejects.toThrow("Disclosure for array element must not have a key");
    });

    // Test 8: Invalid Payload Types
    it("should reject invalid payload structure", async () => {
        // Case 1: _sd is not an array
        const payload1 = {
            _sd: "not an array"
        };
        const jwt1 = await new jose.SignJWT(payload1)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);
        const sdJwt1 = new SDJwt(jwt1, []);
        const verifier = new Verifier();
        await expect(verifier.verify(sdJwt1, pubKey)).rejects.toThrow("_sd must be an array");
        
        // Case 2: _sd element is not a string
        const payload2 = {
            _sd: [123]
        };
        const jwt2 = await new jose.SignJWT(payload2)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);
        const sdJwt2 = new SDJwt(jwt2, []);
        await expect(verifier.verify(sdJwt2, pubKey)).rejects.toThrow("_sd elements must be strings");

        // Case 3: Array element ... is not a string
        const payload3 = {
            array: [{ "...": 123 }]
        };
        const jwt3 = await new jose.SignJWT(payload3)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);
        const sdJwt3 = new SDJwt(jwt3, []);
        await expect(verifier.verify(sdJwt3, pubKey)).rejects.toThrow("Invalid array element digest: 123");
    });

    // Test 9: White Space in Disclosures
    it("should handle whitespace in disclosure JSON", async () => {
        // Manually create a disclosure string with whitespace
        const json = '[\n  "salt",\n  "key",\n  "value"\n]';
        // Encode it
        const encoded = base64UrlEncode(json);
        
        // The digest MUST be over this encoded string
        const digestVal = await digest(encoded, 'SHA-256');
        
        const payload = {
            _sd: [digestVal]
        };
        
        const jwt = await new jose.SignJWT(payload)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);
            
        // Construct SDJwt manually with this encoded string
        // Disclosure.parse should handle it
        const d = await Disclosure.parse(encoded);
        // Manually set encoded back to ensure it matches what we hashed (Disclosure.parse might re-encode if we aren't careful, but my implementation stores .encoded)
        expect(d.encoded).toBe(encoded);
        
        const sdJwt = new SDJwt(jwt, [d]);
        const verifier = new Verifier();
        
        const verified = await verifier.verify(sdJwt, pubKey);
        expect(verified.key).toBe("value");
    });

    // Test 10: Hidden Validity Claims (Security Critical)
    it("should validate validity claims (exp, nbf) even if selectively disclosed", async () => {
        const now = Math.floor(Date.now() / 1000);
        const payload = {
            sub: "user",
            // iat is usually public, but let's verify behavior if critical claims are hidden
        };
        
        const config = {
            exp: true,
            nbf: true
        };
        
        // 1. Create SD-JWT with hidden 'exp' in the past
        const expiredPayload = { ...payload, exp: now - 3600 }; // Expired 1 hour ago
        
        const packer = new SDPacker();
        const { packedPayload: packedExpired, disclosures: disclosuresExpired } = await packer.pack(expiredPayload, config);
        
        const jwtExpired = await new jose.SignJWT(packedExpired)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);
            
        const sdJwtExpired = new SDJwt(jwtExpired, disclosuresExpired);
        const verifier = new Verifier();
        
        // This should fail because it's expired, even though exp is hidden in the JWT
        await expect(verifier.verify(sdJwtExpired, pubKey)).rejects.toThrow();
        
        // 2. Create SD-JWT with hidden 'nbf' in the future
        const futurePayload = { ...payload, nbf: now + 3600 }; // Valid in 1 hour
        
        const packer2 = new SDPacker();
        const { packedPayload: packedFuture, disclosures: disclosuresFuture } = await packer2.pack(futurePayload, config);
        
        const jwtFuture = await new jose.SignJWT(packedFuture)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);
            
        const sdJwtFuture = new SDJwt(jwtFuture, disclosuresFuture);
        
        // This should fail because it's not valid yet
        await expect(verifier.verify(sdJwtFuture, pubKey)).rejects.toThrow();
    });

    //
    // New tests for remaining gaps
    //

    it("should reject repeated digest values in the payload even when disclosures are missing", async () => {
        // Same digest value appears twice in the payload; no disclosure is provided.
        const payload = {
            _sd: ["duplicate-digest", "duplicate-digest"]
        };

        const jwt = await new jose.SignJWT(payload)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);

        const sdJwt = new SDJwt(jwt, []); // No disclosures
        const verifier = new Verifier();

        await expect(verifier.verify(sdJwt, pubKey)).rejects.toThrow();
    });

    it("should prevent issuing disclosures for reserved claim names (_sd and ...)", async () => {
        const payload = { _sd: "visible", ellipsis: "value" };
        const packer = new SDPacker();

        // Attempt to hide a reserved claim name should fail.
        await expect(
            packer.pack(payload, { _sd: true, ellipsis: true })
        ).rejects.toThrow();
    });

    it("should reject nested _sd_alg usage", async () => {
        const payload = { top: { _sd_alg: "sha-256", secret: "x" } };
        const packer = new SDPacker();

        await expect(
            packer.pack(payload, { top: { secret: true } })
        ).rejects.toThrow();
    });

    it("SDJwt.parse returns a Promise and is the single parse entrypoint", async () => {
        const payload = { visible: "ok" };
        const jwt = await new jose.SignJWT(payload)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);

        const sdJwt = new SDJwt(jwt, []);

        // parse is async and should work as the single entrypoint
        const parsed = await SDJwt.parse(sdJwt.toString());
        expect(parsed.jwt).toBe(sdJwt.jwt);
    });
});
