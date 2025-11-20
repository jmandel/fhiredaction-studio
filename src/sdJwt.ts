import { Disclosure } from './disclosure';
import * as jose from 'jose';
import { digest } from './common';

export const DIGEST_ALG_KEY = '_sd_alg';
export const SD_KEY = '_sd';
export const ARRAY_ELEMENT_KEY = '...';

export interface SDJwtPayload {
    [key: string]: any;
    _sd?: string[];
    _sd_alg?: string;
}

export class SDJwt {
    public jwt: string;
    public disclosures: Disclosure[];
    public kbJwt?: string;

    constructor(jwt: string, disclosures: Disclosure[], kbJwt?: string) {
        this.jwt = jwt;
        this.disclosures = disclosures;
        this.kbJwt = kbJwt;
    }

    toString(includeKbJwt: boolean = true): string {
        let result = this.jwt;
        if (this.disclosures.length > 0) {
            result += '~' + this.disclosures.map(d => d.encoded).join('~');
        }
        result += '~'; // Separator before KB-JWT
        if (includeKbJwt && this.kbJwt) {
            result += this.kbJwt;
        }
        return result;
    }

    async calculateSdHash(alg: string = 'SHA-256'): Promise<string> {
        // SD-JWT string without KB-JWT
        const sdJwtString = this.toString(false);
        return await digest(sdJwtString, alg);
    }

    static parse(input: string): SDJwt {
        const parts = input.split('~');
        if (parts.length < 1) {
            throw new Error("Invalid SD-JWT format");
        }

        const jwt = parts[0];
        const disclosures: Disclosure[] = [];
        let kbJwt: string | undefined;

        // Iterate through parts. 
        // Format: <Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~<KB-JWT>
        // If no KB-JWT, it ends with ~
        
        // So all intermediate parts are disclosures. The last part might be empty (if no KB-JWT) or KB-JWT.
        
        const potentialDisclosures = parts.slice(1, parts.length - 1);
        const lastPart = parts[parts.length - 1];

        // However, if there are disclosures, each must be valid.
        // We will parse them asynchronously later or now? 
        // Since parse is sync here (mostly), let's just store strings?
        // But the class expects Disclosure objects.
        // I'll make parse async.
        
        throw new Error("Use parseAsync instead");
    }
    
    static async parseAsync(input: string): Promise<SDJwt> {
        const parts = input.split('~');
        if (parts.length < 2) {
             // It must have at least one ~ at the end
             throw new Error("Invalid SD-JWT format: missing tilde separator");
        }

        const jwt = parts[0];
        const disclosures: Disclosure[] = [];
        let kbJwt: string | undefined;

        // The last element is KB-JWT or empty string
        const lastElement = parts[parts.length - 1];
        if (lastElement !== "") {
            kbJwt = lastElement;
        }

        // Everything in between are disclosures
        for (let i = 1; i < parts.length - 1; i++) {
            const d = parts[i];
            if (d.length > 0) {
                disclosures.push(await Disclosure.parse(d));
            }
        }

        return new SDJwt(jwt, disclosures, kbJwt);
    }

    async getClaims(pubKey: jose.KeyLike | Uint8Array): Promise<any> {
        // Verify the JWT signature
        const { payload } = await jose.jwtVerify(this.jwt, pubKey);
        
        // Reconstruct the object
        return this.reconstruct(payload as SDJwtPayload);
    }
    
    // Simplified reconstruction that assumes all disclosures provided are to be used.
    // In a real verifier, we verify digests.
    private reconstruct(payload: any): any {
         // This is a placeholder. The actual logic is complex and should be in Verifier.
         // This class is mostly a container.
         return payload;
    }
}
