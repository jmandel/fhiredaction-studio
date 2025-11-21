import { Disclosure } from './disclosure';
import { SDJwt, SD_KEY, ARRAY_ELEMENT_KEY, DIGEST_ALG_KEY } from './sdJwt';
import * as jose from 'jose';
import { normalizeHashAlgorithm, base64UrlDecode } from './common';

export class Verifier {
    private usedDisclosures: Set<string> = new Set();
    private seenDigests: Set<string> = new Set();
    private static readonly defaultKbSkewSeconds = 300; // 5 minutes
    private static readonly defaultKbMaxAgeSeconds = 600; // 10 minutes

    async verify(
        sdJwt: SDJwt, 
        pubKey: jose.KeyLike | Uint8Array, 
        kbOptions?: { required?: boolean, nonce?: string, aud?: string, requireValidityClaims?: boolean, now?: number, kbMaxAgeSeconds?: number, kbSkewSeconds?: number }
    ): Promise<any> {
        // 1. Verify the JWT signature
        const verifyOptions = kbOptions?.now
            ? { currentDate: new Date(kbOptions.now * 1000) }
            : undefined;
        const { payload } = await jose.jwtVerify(sdJwt.jwt, pubKey, verifyOptions);
        
        // Determine Hash Algorithm
        const alg = normalizeHashAlgorithm((payload._sd_alg as string) || 'SHA-256');

        // 2. Verify disclosures
        // Map digests to disclosures
        const digestMap = new Map<string, Disclosure>();
        for (const d of sdJwt.disclosures) {
            // Always recalculate/verify digest with the claimed algorithm
            await d.calculateDigest(alg);
            if (digestMap.has(d.digestValue!)) {
                throw new Error(`Duplicate disclosure digest provided: ${d.digestValue}`);
            }
            digestMap.set(d.digestValue!, d);
        }

        this.usedDisclosures.clear();
        this.seenDigests.clear();

        // 3. Reconstruct the object
        const nowSeconds = kbOptions?.now ?? Math.floor(Date.now() / 1000);
        const reconstructed = this.reconstruct(payload, digestMap, true);
        
        // 4. Verify Key Binding if required or present
        if (kbOptions?.required) {
            if (!sdJwt.kbJwt) {
                throw new Error("Key Binding JWT required but missing");
            }
            await this.verifyKbJwt(sdJwt, payload, alg, { ...kbOptions, now: nowSeconds });
        } else if (sdJwt.kbJwt) {
            // If a KB-JWT is present, still validate it fully
            await this.verifyKbJwt(sdJwt, payload, alg, { ...kbOptions, now: nowSeconds });
        }

        // 5. Check for unused disclosures (excluding recursively embedded ones which are handled during reconstruction)
        // Actually, simple check: Iterate all provided disclosures. If digest not found in map lookup during reconstruction?
        // But we might have disclosures inside disclosures.
        // Easier: Track used digests.
        if (this.usedDisclosures.size !== sdJwt.disclosures.length) {
            throw new Error("Unused disclosures found");
        }
        
        // 6. Validate reconstructed claims (exp, nbf, etc.)
        this.validateClaims(reconstructed, kbOptions?.requireValidityClaims === true, nowSeconds);

        return reconstructed;
    }

    private validateClaims(payload: any, strict: boolean, now: number) {
        const clockTolerance = 0; // Could be an option

        // Require exp and nbf to be present and valid when strict mode is on
        if (strict || payload.exp !== undefined) {
            if (payload.exp === undefined) {
                throw new Error("Missing required 'exp' claim");
            }
            if (typeof payload.exp !== 'number') {
                throw new Error("Claim 'exp' must be a number");
            }
            if (now >= payload.exp + clockTolerance) {
                throw new Error(`"exp" claim timestamp check failed`);
            }
        }

        if (strict || payload.nbf !== undefined) {
            if (payload.nbf === undefined) {
                throw new Error("Missing required 'nbf' claim");
            }
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
        options?: { nonce?: string, aud?: string, now?: number, kbMaxAgeSeconds?: number, kbSkewSeconds?: number }
    ) {
        if (!sdJwt.kbJwt) return;

        // Extract cnf from payload
        const cnf = payload.cnf;
        if (!cnf || !cnf.jwk) {
             throw new Error("CNF claim missing or invalid in SD-JWT payload for Key Binding");
        }

        const kbProtectedHeader = this.peekProtectedHeader(sdJwt.kbJwt);
        const headerAlg = kbProtectedHeader.alg;
        const derivedAlg = this.deriveAlgFromJwk(cnf.jwk);
        const holderAlg = headerAlg || derivedAlg;

        if (!this.isAlgCompatibleWithKey(cnf.jwk, holderAlg)) {
            throw new Error("Holder key and KB-JWT alg mismatch");
        }
        const holderPubKey = await jose.importJWK(cnf.jwk, holderAlg);

        // Verify KB-JWT signature
        const { payload: kbPayload, protectedHeader } = await jose.jwtVerify(sdJwt.kbJwt, holderPubKey);
        
        // Verify typ
        if (protectedHeader.typ !== 'kb+jwt') {
            throw new Error("Key Binding JWT must have typ 'kb+jwt'");
        }

        // iat is required and must not be in the future (allow small clock skew)
        if (typeof kbPayload.iat !== 'number') {
            throw new Error("KB-JWT must contain numeric iat");
        }
        const now = options?.now ?? Math.floor(Date.now() / 1000);
        const skew = options?.kbSkewSeconds ?? Verifier.defaultKbSkewSeconds;
        if (kbPayload.iat > now + skew) {
            throw new Error("KB-JWT iat is in the future");
        }
        const maxAge = options?.kbMaxAgeSeconds ?? Verifier.defaultKbMaxAgeSeconds;
        if (typeof maxAge === 'number' && isFinite(maxAge)) {
            if (kbPayload.iat < now - maxAge) {
                throw new Error("KB-JWT iat is too old");
            }
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
        
        // Verify nonce and aud if provided / required
        if (options?.nonce) {
            if (kbPayload.nonce !== options.nonce) {
                throw new Error("KB-JWT nonce mismatch");
            }
        } else {
            if (kbPayload.nonce === undefined) {
                throw new Error("KB-JWT missing nonce");
            }
        }
        
        if (options?.aud) {
            if (kbPayload.aud !== options.aud) {
                 throw new Error("KB-JWT aud mismatch");
            }
        } else {
            if (kbPayload.aud === undefined) {
                throw new Error("KB-JWT missing aud");
            }
        }
    }

    // Extract protected header without verifying to decide algorithm
    private peekProtectedHeader(jwt: string): jose.JWSHeaderParameters {
        const [protectedHeader] = jwt.split('.');
        const json = new TextDecoder().decode(base64UrlDecode(protectedHeader));
        return JSON.parse(json);
    }

    private deriveAlgFromJwk(jwk: any): string {
        if (jwk.alg) return jwk.alg;
        if (jwk.crv === 'P-256') return 'ES256';
        if (jwk.crv === 'P-384') return 'ES384';
        if (jwk.crv === 'P-521') return 'ES512';
        if (jwk.kty === 'OKP' && jwk.crv && jwk.crv.startsWith('Ed')) return 'EdDSA';
        if (jwk.kty === 'RSA') return 'RS256';
        throw new Error("Unable to derive algorithm from holder key");
    }

    private isAlgCompatibleWithKey(jwk: any, alg?: string): boolean {
        if (!alg) return false;
        if (jwk.alg && jwk.alg !== alg) return false;

        if (jwk.kty === 'RSA') {
            return ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'].includes(alg);
        }
        if (jwk.kty === 'OKP' && jwk.crv && jwk.crv.startsWith('Ed')) {
            return alg === 'EdDSA';
        }
        if (jwk.kty === 'EC') {
            if (jwk.crv === 'P-256') return alg === 'ES256';
            if (jwk.crv === 'P-384') return alg === 'ES384';
            if (jwk.crv === 'P-521') return alg === 'ES512';
        }
        return false;
    }

    private reconstruct(input: any, digestMap: Map<string, Disclosure>, isRoot: boolean = false): any {
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

                    if (this.seenDigests.has(digest)) {
                        throw new Error("Duplicate digest value in payload");
                    }
                    this.seenDigests.add(digest);

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
                        result.push(this.reconstruct(disclosure.value, digestMap, false));
                    }
                    // If disclosure not found, we omit the element (it is not disclosed or is a decoy)
                } else {
                    result.push(this.reconstruct(item, digestMap, false));
                }
            }
            return result;
        }

        // Object
        const result: any = {};
        const sdDigests = input[SD_KEY]; // Array of strings

        // Copy plain properties, stripping control claims
        for (const [key, value] of Object.entries(input)) {
            if (key === DIGEST_ALG_KEY && !isRoot) {
                throw new Error("_sd_alg must only appear at top level");
            }
            if (key === SD_KEY || key === DIGEST_ALG_KEY) {
                continue;
            }
            result[key] = this.reconstruct(value, digestMap, false);
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

                if (this.seenDigests.has(digest)) {
                    throw new Error("Duplicate digest value in payload");
                }
                this.seenDigests.add(digest);
                
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
                    result[disclosure.key] = this.reconstruct(disclosure.value, digestMap, false);
                }
                // If not found, it's a decoy or undisclosed.
            }
        }

        // At root, ensure control claims are not present in the processed payload
        if (isRoot) {
            delete result._sd;
            delete result._sd_alg;
        }

        return result;
    }
}
