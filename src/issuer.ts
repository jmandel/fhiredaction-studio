import { Disclosure } from './disclosure';
import { SDJwt, SDJwtPayload, SD_KEY, ARRAY_ELEMENT_KEY } from './sdJwt';
import * as jose from 'jose';
import { generateSalt, digest } from './common';

export class SDPacker {
    private disclosures: Disclosure[] = [];
    private saltGenerator?: () => string;
    private hashAlg: string;

    constructor(saltGenerator?: () => string, hashAlg: string = 'SHA-256') {
        this.saltGenerator = saltGenerator;
        this.hashAlg = hashAlg;
    }

    async pack(payload: any, disclosureConfig: any): Promise<any> {
        if (typeof payload !== 'object' || payload === null) {
            return payload;
        }

        if (Array.isArray(payload)) {
             // Determine array configuration
             let itemsConfig: any[] | null = null;
             let decoysCount = 0;

             if (Array.isArray(disclosureConfig)) {
                 itemsConfig = disclosureConfig;
                 // Support attached property if present (less standard but possible in JS)
                 if ((disclosureConfig as any)._decoys) {
                     decoysCount = (disclosureConfig as any)._decoys;
                 }
             } else if (typeof disclosureConfig === 'object' && disclosureConfig !== null) {
                 // Support object wrapper: { _items: [...], _decoys: N }
                 if (Array.isArray(disclosureConfig._items)) {
                     itemsConfig = disclosureConfig._items;
                 }
                 if (typeof disclosureConfig._decoys === 'number') {
                     decoysCount = disclosureConfig._decoys;
                 }
             }

             // Handle array
             const packedArray = [];
             for (let i = 0; i < payload.length; i++) {
                 const val = payload[i];
                 const config = itemsConfig ? itemsConfig[i] : null;
                 
                 if (config === true) {
                     // Conceal this element
                     const d = await Disclosure.create(await this.pack(val, null), undefined, this.saltGenerator ? this.saltGenerator() : undefined);
                     await d.calculateDigest(this.hashAlg);
                     this.disclosures.push(d);
                     packedArray.push({ [ARRAY_ELEMENT_KEY]: d.digestValue });
                 } else if (typeof config === 'object') {
                     packedArray.push(await this.pack(val, config));
                 } else {
                     packedArray.push(val);
                 }
             }
             
             // Handle array decoys
             for(let i=0; i<decoysCount; i++) {
                packedArray.push({ [ARRAY_ELEMENT_KEY]: await this.createDecoyDigest() });
             }
             
             return packedArray;
        }

        // Object
        const packedObject: any = {};
        const sdDigests: string[] = [];

        for (const [key, val] of Object.entries(payload)) {
            const config = disclosureConfig ? disclosureConfig[key] : undefined;
            
            if (config === true) {
                const d = await Disclosure.create(val, key, this.saltGenerator ? this.saltGenerator() : undefined);
                await d.calculateDigest(this.hashAlg);
                this.disclosures.push(d);
                sdDigests.push(d.digestValue!);
            } else if (typeof config === 'object') {
                 // Check if we need to conceal THIS key as well as nested
                 const concealSelf = config._self === true;
                 
                 // Process nested first
                 // Remove _self and _decoys from config for nested processing
                 let nestedConfig;
                 if (Array.isArray(config)) {
                    nestedConfig = config;
                 } else {
                    const { _self, ...rest } = config;
                    // We must preserve _decoys (and _items for arrays) for the recursive call
                    // because they configure the internal structure of the value.
                    // _self is consumed here.
                    nestedConfig = rest;
                 }

                 const processedVal = await this.pack(val, nestedConfig);
                 
                 if (concealSelf) {
                     const d = await Disclosure.create(processedVal, key, this.saltGenerator ? this.saltGenerator() : undefined);
                     await d.calculateDigest(this.hashAlg);
                     this.disclosures.push(d);
                     sdDigests.push(d.digestValue!);
                 } else {
                     packedObject[key] = processedVal;
                 }
            } else {
                packedObject[key] = val;
            }
        }

        // Handle object decoys
        if (disclosureConfig && disclosureConfig._decoys) {
             const count = disclosureConfig._decoys;
             for(let i=0; i<count; i++) {
                 sdDigests.push(await this.createDecoyDigest());
             }
        }

        if (sdDigests.length > 0) {
            // Shuffle digests (both disclosures and decoys)
            // Simple shuffle
            for (let i = sdDigests.length - 1; i > 0; i--) {
                const j = Math.floor(Math.random() * (i + 1));
                [sdDigests[i], sdDigests[j]] = [sdDigests[j], sdDigests[i]];
            }
            packedObject[SD_KEY] = sdDigests;
        }

        return packedObject;
    }
    
    private async createDecoyDigest(): Promise<string> {
        const salt = this.saltGenerator ? this.saltGenerator() : generateSalt();
        // Spec says: hash over a cryptographically secure random number.
        // But we usually hash base64url encoded things. 
        // "It is RECOMMENDED to create the decoy digests by hashing over a cryptographically secure random number. The bytes of the digest MUST then be base64url encoded."
        // So digest(random_string).
        return await digest(salt, this.hashAlg);
    }

    getDisclosures(): Disclosure[] {
        return this.disclosures;
    }
}
