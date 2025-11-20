import { base64UrlEncode, base64UrlDecodeToString, digest, generateSalt } from './common';

export type DisclosureArray = [string, string, any] | [string, any];

export class Disclosure {
    public salt: string;
    public key: string | undefined;
    public value: any;
    public encoded: string;
    public digestValue: string | undefined;

    constructor(salt: string, value: any, key?: string) {
        this.salt = salt;
        this.value = value;
        this.key = key;
        
        const array: DisclosureArray = key !== undefined 
            ? [salt, key, value] 
            : [salt, value];
            
        const json = JSON.stringify(array);
        this.encoded = base64UrlEncode(new TextEncoder().encode(json));
    }

    static async create(value: any, key?: string, salt?: string): Promise<Disclosure> {
        const s = salt || generateSalt();
        const disclosure = new Disclosure(s, value, key);
        await disclosure.calculateDigest();
        return disclosure;
    }

    static async parse(encoded: string): Promise<Disclosure> {
        try {
            const json = base64UrlDecodeToString(encoded);
            const array = JSON.parse(json);
            
            if (!Array.isArray(array)) {
                throw new Error("Disclosure must be an array");
            }
            
            let salt: string;
            let key: string | undefined;
            let value: any;

            if (array.length === 3) {
                [salt, key, value] = array;
                if (typeof key !== 'string') {
                     throw new Error("Disclosure key must be a string");
                }
            } else if (array.length === 2) {
                [salt, value] = array;
            } else {
                throw new Error("Disclosure array must have 2 or 3 elements");
            }
            
            if (typeof salt !== 'string') {
                throw new Error("Disclosure salt must be a string");
            }

            const disclosure = new Disclosure(salt, value, key);
            // Verify that the re-encoded disclosure matches the input
            // Actually, the spec says "The digest is calculated over the respective base64url-encoded value itself, which effectively signs the variation chosen by the Issuer"
            // So we should keep the original encoded string if possible, OR we accept that we might re-encode it differently if we don't store it.
            // But here we are parsing, so we should store the original encoded string.
            disclosure.encoded = encoded;
            await disclosure.calculateDigest();
            return disclosure;
        } catch (e) {
            throw new Error(`Failed to parse disclosure: ${e}`);
        }
    }

    async calculateDigest(alg: string = 'SHA-256') {
        this.digestValue = await digest(this.encoded, alg);
    }
}
