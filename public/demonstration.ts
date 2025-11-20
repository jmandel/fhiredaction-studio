import { SDPacker, SDJwt, Verifier } from '../src/index';
import * as jose from 'jose';

// Mock key pair generation for browser
async function generateKeyPair() {
    return await jose.generateKeyPair('ES256', { extractable: true });
}

async function runDemo() {
    const output = document.getElementById('output') as HTMLElement;
    const log = (msg: string) => {
        output.innerText += msg + '\n';
    };

    log("Generating keys...");
    const { publicKey, privateKey } = await generateKeyPair();
    
    const payload = {
        sub: "user_123",
        name: "Alice",
        email: "alice@example.com",
        address: {
            street: "123 Wonderland",
            city: "Magic City"
        },
        hobbies: ["chess", "reading"]
    };

    log("\nOriginal Payload:");
    log(JSON.stringify(payload, null, 2));

    // Config: Hide email and address.city, and first hobby
    const config = {
        email: true,
        address: {
            city: true
        },
        hobbies: [true, false]
    };
    
    log("\nDisclosure Config:");
    log(JSON.stringify(config, null, 2));

    log("\nCreating SD-JWT...");
    const packer = new SDPacker();
    const packedPayload = await packer.pack(payload, config);
    
    const jwt = await new jose.SignJWT(packedPayload)
        .setProtectedHeader({ alg: 'ES256' })
        .sign(privateKey);
        
    const disclosures = packer.getDisclosures();
    const sdJwt = new SDJwt(jwt, disclosures);
    const serialized = sdJwt.toString();
    
    log("\nSerialized SD-JWT:");
    log(serialized);
    
    log("\nVerifying and Reconstructing...");
    const verifier = new Verifier();
    const parsed = await SDJwt.parseAsync(serialized);
    const verified = await verifier.verify(parsed, publicKey);
    
    log("\nVerified Claims:");
    log(JSON.stringify(verified, null, 2));
    
    log("\nDemonstrating Key Binding (Simplified)...");
    // Generate KB-JWT
    const sdHash = await sdJwt.calculateSdHash();
    const kbJwt = await new jose.SignJWT({
        nonce: "123",
        aud: "verifier",
        iat: Math.floor(Date.now() / 1000),
        sd_hash: sdHash
    })
    .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
    .sign(privateKey);
    
    sdJwt.kbJwt = kbJwt;
    log("Added KB-JWT to SD-JWT.");
    
    // Interactive part: Let user toggle disclosures
    const interactiveDiv = document.getElementById('interactive') as HTMLElement;
    interactiveDiv.innerHTML = "<h3>Selective Disclosure Interactive Demo</h3>";
    
    // We can simulate "holding" the credential and selecting disclosures.
    // We have `disclosures` array.
    
    const state = disclosures.map(d => ({ disclosure: d, selected: true }));
    
    const render = async () => {
        const selectedDisclosures = state.filter(s => s.selected).map(s => s.disclosure);
        const subsetSdJwt = new SDJwt(jwt, selectedDisclosures);
        
        let verifiedSubset = {};
        try {
            verifiedSubset = await verifier.verify(subsetSdJwt, publicKey);
        } catch (e) {
            verifiedSubset = { error: String(e) };
        }
        
        const checkboxes = state.map((s, idx) => `
            <div>
                <input type="checkbox" id="disc-${idx}" ${s.selected ? 'checked' : ''} onchange="window.toggleDisclosure(${idx})">
                <label for="disc-${idx}">Disclose: ${s.disclosure.key ? s.disclosure.key : 'Array Element'}: ${JSON.stringify(s.disclosure.value)}</label>
            </div>
        `).join('');
        
        interactiveDiv.innerHTML = `
            ${checkboxes}
            <h4>Verified Payload with Selected Disclosures:</h4>
            <pre>${JSON.stringify(verifiedSubset, null, 2)}</pre>
            <p>SD-JWT String Length: ${subsetSdJwt.toString().length}</p>
        `;
    };

    (window as any).toggleDisclosure = (idx: number) => {
        state[idx].selected = !state[idx].selected;
        render();
    };
    
    render();
}

runDemo().catch(console.error);
