import { Disclosure } from './disclosure';
import { SDJwt, SD_KEY, ARRAY_ELEMENT_KEY } from './sdJwt';
import * as jose from 'jose';

export class Verifier {
    private usedDisclosures: Set<string> = new Set();

    async verify(
        sdJwt: SDJwt, 
        pubKey: jose.KeyLike | Uint8Array, 
        kbOptions?: { required: boolean, nonce?: string, aud?: string }
    ): Promise<any> {
        // 1. Verify the JWT signature
        const { payload, protectedHeader } = await jose.jwtVerify(sdJwt.jwt, pubKey);
        
        // Determine Hash Algorithm
        const alg = (payload._sd_alg as string) || 'SHA-256';

        // 2. Verify disclosures
        // Map digests to disclosures
        const digestMap = new Map<string, Disclosure>();
        for (const d of sdJwt.disclosures) {
            // Always recalculate/verify digest with the claimed algorithm
            await d.calculateDigest(alg);
            digestMap.set(d.digestValue!, d);
        }

        this.usedDisclosures.clear();

        // 3. Reconstruct the object
        const reconstructed = this.reconstruct(payload, digestMap);
        
        // 4. Verify Key Binding if required or present
        if (kbOptions?.required) {
            if (!sdJwt.kbJwt) {
                throw new Error("Key Binding JWT required but missing");
            }
            await this.verifyKbJwt(sdJwt, payload, alg, kbOptions);
        } else if (sdJwt.kbJwt) {
            await this.verifyKbJwt(sdJwt, payload, alg, kbOptions);
        }

        // 5. Check for unused disclosures (excluding recursively embedded ones which are handled during reconstruction)
        // Actually, simple check: Iterate all provided disclosures. If digest not found in map lookup during reconstruction?
        // But we might have disclosures inside disclosures.
        // Easier: Track used digests.
        if (this.usedDisclosures.size !== sdJwt.disclosures.length) {
            throw new Error("Unused disclosures found");
        }
        
        // 6. Validate reconstructed claims (exp, nbf, etc.)
        // jose.jwtVerify only validated the signed payload. If validity claims were hidden, they were not checked.
        // We must check them now on the reconstructed object.
        this.validateClaims(reconstructed);

        return reconstructed;
    }

    private validateClaims(payload: any) {
        const now = Math.floor(Date.now() / 1000);
        const clockTolerance = 0; // Could be an option

        if (payload.exp !== undefined) {
            if (typeof payload.exp !== 'number') {
                throw new Error("Claim 'exp' must be a number");
            }
            if (now >= payload.exp + clockTolerance) {
                throw new Error(`"exp" claim timestamp check failed`);
            }
        }

        if (payload.nbf !== undefined) {
            if (typeof payload.nbf !== 'number') {
                throw new Error("Claim 'nbf' must be a number");
            }
            if (now < payload.nbf - clockTolerance) {
                throw new Error(`"nbf" claim timestamp check failed`);
            }
        }
        
        // Can add 'aud', 'iss' checks here if options are provided in the future
    }

    private async verifyKbJwt(
        sdJwt: SDJwt, 
        payload: any, 
        alg: string, 
        options?: { nonce?: string, aud?: string }
    ) {
        if (!sdJwt.kbJwt) return;

        // Extract cnf from payload
        const cnf = payload.cnf;
        if (!cnf || !cnf.jwk) {
             throw new Error("CNF claim missing or invalid in SD-JWT payload for Key Binding");
        }
        const holderPubKey = await jose.importJWK(cnf.jwk, 'ES256'); // Algorithm might vary

        // Verify KB-JWT signature
        const { payload: kbPayload, protectedHeader } = await jose.jwtVerify(sdJwt.kbJwt, holderPubKey);
        
        // Verify typ
        if (protectedHeader.typ !== 'kb+jwt') {
            throw new Error("Key Binding JWT must have typ 'kb+jwt'");
        }

        // Verify sd_hash
        const sdHash = kbPayload.sd_hash;
        if (!sdHash) {
             throw new Error("sd_hash missing in KB-JWT");
        }
        
        // Calculate expected hash using the algorithm specified in _sd_alg (or SHA-256)
        const expectedHash = await sdJwt.calculateSdHash(alg);
        if (sdHash !== expectedHash) {
            throw new Error("sd_hash mismatch");
        }
        
        // Verify nonce and aud if provided
        if (options?.nonce && kbPayload.nonce !== options.nonce) {
            throw new Error("KB-JWT nonce mismatch");
        }
        
        if (options?.aud && kbPayload.aud !== options.aud) {
             throw new Error("KB-JWT aud mismatch");
        }
    }

    private reconstruct(input: any, digestMap: Map<string, Disclosure>): any {
        if (typeof input !== 'object' || input === null) {
            return input;
        }

        if (Array.isArray(input)) {
            const result: any[] = [];
            for (const item of input) {
                if (typeof item === 'object' && item !== null && ARRAY_ELEMENT_KEY in item) {
                    const digest = item[ARRAY_ELEMENT_KEY];
                    if (typeof digest !== 'string') {
                         // If ... is present but not a string, is it a valid object? 
                         // Spec says: "The key MUST always be the string ... . The value MUST be the digest ... There MUST NOT be any other keys".
                         // If it has other keys, it's a regular object?
                         // But we are inside an array.
                         // "For each digest, an object of the form {"...": "<digest>"} is added... There MUST NOT be any other keys in the object."
                         // A robust verifier should probably treat it as a regular object if it fails this strict check?
                         // Or strictly reject?
                         // Let's strictly reject if '...' is present but invalid type.
                         throw new Error(`Invalid array element digest: ${digest}`);
                    }

                    if (Object.keys(item).length > 1) {
                        throw new Error("Array element object with '...' must not have other keys");
                    }

                    const disclosure = digestMap.get(digest);
                    
                    if (disclosure) {
                        if (this.usedDisclosures.has(digest)) {
                            throw new Error(`Duplicate digest usage: ${digest}`);
                        }
                        
                        // Strict check: Array disclosures must NOT have a key (2 elements)
                        if (disclosure.key !== undefined) {
                            throw new Error("Disclosure for array element must not have a key");
                        }

                        this.usedDisclosures.add(digest);
                        
                        // Recursive processing of the disclosed value
                        result.push(this.reconstruct(disclosure.value, digestMap));
                    }
                    // If disclosure not found, we omit the element (it is not disclosed or is a decoy)
                } else {
                    result.push(this.reconstruct(item, digestMap));
                }
            }
            return result;
        }

        // Object
        const result: any = {};
        const sdDigests = input[SD_KEY]; // Array of strings

        // Copy plain properties
        for (const [key, value] of Object.entries(input)) {
            if (key !== SD_KEY) {
                result[key] = this.reconstruct(value, digestMap);
            }
        }

        // Apply disclosures
        if (sdDigests !== undefined) {
            if (!Array.isArray(sdDigests)) {
                // If _sd is present but not an array, it's invalid? 
                // Spec: "The _sd key MUST refer to an array of strings"
                // If it's not an array, we should probably reject it or treat it as malformed.
                // However, if it's a user claim named "_sd" that is NOT the special key?
                // "The payload MUST NOT contain the claims _sd ... except for the purpose of conveying digests"
                // So if it exists, it MUST be an array of strings.
                 throw new Error("_sd must be an array");
            }

            for (const digest of sdDigests) {
                if (typeof digest !== 'string') {
                    throw new Error("_sd elements must be strings");
                }
                
                const disclosure = digestMap.get(digest);
                if (disclosure) {
                     if (this.usedDisclosures.has(digest)) {
                        throw new Error(`Duplicate digest usage: ${digest}`);
                    }

                    // Strict check: Object disclosures MUST have a key (3 elements)
                    if (disclosure.key === undefined) {
                        throw new Error("Disclosure for object property must have a key");
                    }

                    this.usedDisclosures.add(digest);

                    // Collision check? Spec says: "If the claim name already exists at the level of the _sd key, the SD-JWT MUST be rejected."
                    if (disclosure.key in result) {
                        throw new Error(`Claim name collision: ${disclosure.key}`);
                    }
                    result[disclosure.key] = this.reconstruct(disclosure.value, digestMap);
                }
                // If not found, it's a decoy or undisclosed.
            }
        }

        return result;
    }
}
