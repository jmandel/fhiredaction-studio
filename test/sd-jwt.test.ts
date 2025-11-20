import { describe, it, expect, beforeAll } from "bun:test";
import * as jose from 'jose';
import { SDPacker } from '../src/issuer';
import { SDJwt } from '../src/sdJwt';
import { Verifier } from '../src/verifier';
import { Disclosure } from '../src/disclosure';

describe("SD-JWT", () => {
    let keyPair: any;
    let pubKey: any;
    let privKey: any;

    beforeAll(async () => {
        keyPair = await jose.generateKeyPair('ES256');
        pubKey = keyPair.publicKey;
        privKey = keyPair.privateKey;
    });

    it("should create and verify a simple SD-JWT", async () => {
        const payload = {
            sub: "user_42",
            given_name: "John",
            family_name: "Doe",
            email: "johndoe@example.com",
            phone_number: "+1-202-555-0101",
            address: {
                street_address: "123 Main St",
                locality: "Anytown",
                region: "Anystate",
                country: "US"
            }
        };

        const disclosureConfig = {
            given_name: true,
            family_name: true,
            address: {
                street_address: true,
                _self: true // Conceal the address object itself AND recursively its properties
            }
        };

        // Pack
        const packer = new SDPacker();
        const packedPayload = await packer.pack(payload, disclosureConfig);
        const disclosures = packer.getDisclosures();

        // Sign
        const jwt = await new jose.SignJWT(packedPayload)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);

        const sdJwt = new SDJwt(jwt, disclosures);
        const serialized = sdJwt.toString();
        
        console.log("Serialized SD-JWT:", serialized);

        // Parse
        const parsedSdJwt = await SDJwt.parseAsync(serialized);
        expect(parsedSdJwt.disclosures.length).toBe(disclosures.length);

        // Verify
        const verifier = new Verifier();
        const verifiedClaims = await verifier.verify(parsedSdJwt, pubKey);
        
        console.log("Verified Claims:", verifiedClaims);

        expect(verifiedClaims.sub).toBe("user_42");
        expect(verifiedClaims.given_name).toBe("John");
        expect(verifiedClaims.family_name).toBe("Doe");
        expect(verifiedClaims.address.street_address).toBe("123 Main St");
    });
    
    it("should handle array elements", async () => {
        const payload = {
            nationalities: ["US", "DE"]
        };
        
        const disclosureConfig = {
            nationalities: [true, false] // Conceal first element
        };
        
        const packer = new SDPacker();
        const packedPayload = await packer.pack(payload, disclosureConfig);
        
        // Expect packedPayload.nationalities[0] to be { "...": <digest> }
        // Access using bracket notation and check definition
        expect(packedPayload.nationalities[0]['...']).toBeDefined();
        expect(packedPayload.nationalities[1]).toBe("DE");
        
         // Sign
        const jwt = await new jose.SignJWT(packedPayload)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);

        const sdJwt = new SDJwt(jwt, packer.getDisclosures());
        
        const verifier = new Verifier();
        const verifiedClaims = await verifier.verify(sdJwt, pubKey);
        
        expect(verifiedClaims.nationalities).toContain("US");
        expect(verifiedClaims.nationalities).toContain("DE");
    });

    it("should handle array elements where some disclosures are missing", async () => {
        const payload = {
            nationalities: ["US", "DE"]
        };
        
        const disclosureConfig = {
            nationalities: [true, true] 
        };
        
        const packer = new SDPacker();
        const packedPayload = await packer.pack(payload, disclosureConfig);
        
         // Sign
        const jwt = await new jose.SignJWT(packedPayload)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);

        const disclosures = packer.getDisclosures();
        // Drop one disclosure (e.g. "US")
        // We need to know which one is which. The packer stores them in order of creation.
        // US is first.
        const disclosuresToSend = disclosures.slice(1);

        const sdJwt = new SDJwt(jwt, disclosuresToSend);
        
        const verifier = new Verifier();
        const verifiedClaims = await verifier.verify(sdJwt, pubKey);
        
        expect(verifiedClaims.nationalities).toHaveLength(1);
        expect(verifiedClaims.nationalities[0]).toBe("DE");
    });

    it("should support decoy digests", async () => {
        const payload = {
            secret: "value"
        };
        const config = {
            secret: true,
            _decoys: 2
        };
        const packer = new SDPacker();
        const packed = await packer.pack(payload, config);
        
        expect(packed._sd).toBeDefined();
        expect(packed._sd.length).toBe(3); // 1 disclosure + 2 decoys
    });

    it("should support key binding", async () => {
        const payload = {
            sub: "holder",
            cnf: {
                jwk: await jose.exportJWK(pubKey)
            }
        };
        
        // Pack (no disclosures for simplicity, just testing KB)
        const packer = new SDPacker();
        const packedPayload = await packer.pack(payload, {});
        
        // Issuer signs
        const jwt = await new jose.SignJWT(packedPayload)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);
            
        const sdJwt = new SDJwt(jwt, []);
        
        // Calculate sd_hash
        const sdHash = await sdJwt.calculateSdHash();
        
        // Holder creates KB-JWT
        const kbJwt = await new jose.SignJWT({
            nonce: "123",
            aud: "verifier",
            iat: Math.floor(Date.now() / 1000),
            sd_hash: sdHash
        })
        .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
        .sign(privKey); // Holder uses same key for simplicity in this test
        
        sdJwt.kbJwt = kbJwt;
        
        const verifier = new Verifier();
        await verifier.verify(sdJwt, pubKey, true);
    });

    it("should fail if unused disclosures are present", async () => {
        const payload = { a: 1 };
        const config = { a: true };
        const packer = new SDPacker();
        const packed = await packer.pack(payload, config);
        
        const jwt = await new jose.SignJWT(packed)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);
            
        // Add an extra disclosure that isn't used
        const extraDisclosure = await Disclosure.create("unused", "b");
        const disclosures = [...packer.getDisclosures(), extraDisclosure];
        
        const sdJwt = new SDJwt(jwt, disclosures);
        const verifier = new Verifier();
        
        expect(verifier.verify(sdJwt, pubKey)).rejects.toThrow("Unused disclosures found");
    });

    it("should support complex nested structures and array decoys using object config", async () => {
        const payload = {
            nested: {
                array: [1, 2, 3]
            }
        };

        // Config:
        // - 'nested' object: add 1 decoy
        // - 'array': conceal element at index 1 (value 2), add 2 decoys
        const config = {
            nested: {
                _decoys: 1,
                array: {
                    _items: [false, true, false], // conceal index 1
                    _decoys: 2
                }
            }
        };

        const packer = new SDPacker();
        const packed = await packer.pack(payload, config);

        // Verify object structure and decoys
        expect(packed.nested._sd).toBeDefined();
        expect(packed.nested._sd.length).toBe(1); // 1 decoy

        // Verify array structure and decoys
        const array = packed.nested.array;
        expect(array.length).toBe(3 + 2); // 3 original + 2 decoys

        // Check elements: 1, {...}, 3, {...}, {...} (order of decoys is appended, but usually shuffled if in _sd, but for arrays they are just appended by packer logic currently, though spec suggests shuffling/positioning? Spec: "It is RECOMMENDED to create the decoy digests... Decoy digests MAY be added ... in arrays." "Issuer MUST hide the original order... RECOMMENDED to shuffle the array of hashes [in _sd]". For array elements: "Digests ... added to the array in the same position ... Decoy digests MAY be added ... in arrays". If appended, size is leaked partially. But for this test, we check existence.)
        
        // Expect index 1 to be replaced
        expect(array[0]).toBe(1);
        expect(array[1]['...']).toBeDefined(); // The disclosure digest
        expect(array[2]).toBe(3);
        // Decoys at end (based on implementation)
        expect(array[3]['...']).toBeDefined();
        expect(array[4]['...']).toBeDefined();

        // Verify full cycle
        const jwt = await new jose.SignJWT(packed)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privKey);
        
        const sdJwt = new SDJwt(jwt, packer.getDisclosures());
        const verifier = new Verifier();
        const verified = await verifier.verify(sdJwt, pubKey);

        expect(verified.nested.array).toEqual([1, 2, 3]);
    });
});
