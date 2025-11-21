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

  static async parse(input: string): Promise<SDJwt> {
    const parts = input.split('~');
    if (parts.length < 2) {
        throw new Error("Invalid SD-JWT format: missing separators");
    }

    const hasTrailingSeparator = input.endsWith('~');
    const lastElement = parts[parts.length - 1];
    const isKbJwt = lastElement !== "";

    if (!isKbJwt && !hasTrailingSeparator) {
        throw new Error("Invalid SD-JWT format: missing trailing separator");
    }
    if (isKbJwt && lastElement.split('.').length !== 3) {
        throw new Error("Invalid SD-JWT format: final component must be a JWT when present");
    }

    const jwt = parts[0];
    const disclosures: Disclosure[] = [];
    let kbJwt: string | undefined = isKbJwt ? lastElement : undefined;

    for (let i = 1; i < parts.length - 1; i++) {
        const d = parts[i];
        if (d.length > 0) {
            disclosures.push(await Disclosure.parse(d));
        }
    }

    return new SDJwt(jwt, disclosures, kbJwt);
  }

    async getClaims(pubKey: jose.KeyLike | Uint8Array): Promise<any> {
        throw new Error("SDJwt.getClaims is deprecated. Use Verifier.verify for secure processing.");
    }
}
