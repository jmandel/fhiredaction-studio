import { SDJwt } from '../../core/src/index';
import * as jose from 'jose';
import { writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { packFhirSdJwt } from '../src/autoSdJwt';

// --- FHIR Fixtures ---

const patient = {
    resourceType: "Patient",
    id: "p1",
    active: true,
    name: [{
        family: "Smart",
        given: ["Alice", "J"],
        text: "Alice J. Smart"
    }],
    identifier: [
        {
            system: "http://hospital.example.org/mrn",
            value: "MRN-12345",
            type: { coding: [{ system: "http://terminology.hl7.org/CodeSystem/v2-0203", code: "MR" }] }
        },
        {
            system: "http://hl7.org/fhir/sid/us-ssn",
            value: "000-00-0000",
            type: { coding: [{ system: "http://terminology.hl7.org/CodeSystem/v2-0203", code: "SSN" }] }
        },
        {
            system: "http://dmv.example.org/dl",
            value: "DL-987654321",
            type: { coding: [{ system: "http://terminology.hl7.org/CodeSystem/v2-0203", code: "DL" }] }
        }
    ],
    telecom: [
        {
            system: "phone",
            value: "555-555-5555",
            use: "mobile"
        },
        {
            system: "email",
            value: "alice@example.com",
            use: "home"
        }
    ],
    address: [
        {
            use: "home",
            line: ["123 Rabbit Hole"],
            city: "Wonderland",
            state: "CA",
            postalCode: "12345"
        },
        {
            use: "work",
            line: ["456 Corporate Blvd"],
            city: "Metropolis",
            state: "NY",
            postalCode: "54321"
        }
    ],
    birthDate: "1980-01-01"
};

const bundle = {
    resourceType: "Bundle",
    type: "collection",
    entry: [
        {
            fullUrl: "https://sd.example.org/fhir/Patient/p1",
            resource: patient
        },
        {
            fullUrl: "https://sd.example.org/fhir/Condition/c1",
            resource: {
                resourceType: "Condition",
                id: "c1",
                subject: { reference: "Patient/p1" },
                clinicalStatus: { coding: [{ system: "http://terminology.hl7.org/CodeSystem/condition-clinical", code: "active" }] },
                code: { coding: [{ system: "http://snomed.info/sct", code: "44054006", display: "Type 2 diabetes mellitus" }] }
            }
        },
        {
            fullUrl: "https://sd.example.org/fhir/Observation/o1",
            resource: {
                resourceType: "Observation",
                id: "o1",
                status: "final",
                subject: { reference: "Patient/p1" },
                code: { coding: [{ system: "http://loinc.org", code: "29463-7", display: "Body Weight" }] },
                valueQuantity: { value: 70, unit: "kg", system: "http://unitsofmeasure.org", code: "kg" }
            }
        },
        {
            fullUrl: "https://sd.example.org/fhir/AllergyIntolerance/a1",
            resource: {
                resourceType: "AllergyIntolerance",
                id: "a1",
                patient: { reference: "Patient/p1" },
                clinicalStatus: { coding: [{ system: "http://terminology.hl7.org/CodeSystem/allergyintolerance-clinical", code: "active" }] },
                code: { coding: [{ system: "http://snomed.info/sct", code: "39579001", display: "Anaphylaxis" }] }
            }
        },
        {
            fullUrl: "https://sd.example.org/fhir/Immunization/i1",
            resource: {
                resourceType: "Immunization",
                id: "i1",
                status: "completed",
                patient: { reference: "Patient/p1" },
                vaccineCode: { coding: [{ system: "http://hl7.org/fhir/sid/cvx", code: "207", display: "COVID-19, mRNA, LNP-S, PF, 100 mcg/0.5mL dose" }] },
                occurrenceDateTime: "2021-01-01",
                location: { reference: "#loc1", display: "Free Clinic" },
                contained: [
                    {
                        resourceType: "Location",
                        id: "loc1",
                        name: "Downtown Free Clinic",
                        address: {
                            line: ["100 Skid Row"],
                            city: "Metropolis",
                            state: "NY",
                            postalCode: "54321"
                        }
                    }
                ]
            }
        }
    ]
};

// --- Generation ---

async function generate() {
    console.log("Generating keys...");
    const { publicKey, privateKey } = await jose.generateKeyPair('ES256', { extractable: true });
    const publicJwk = await jose.exportJWK(publicKey);
    const privateJwk = await jose.exportJWK(privateKey);

    console.log("Packing SD-JWT...");
    // 3. Pack into SD-JWT using the FHIR auto packer (per-element selective disclosure)
    const { packedPayload, disclosures } = await packFhirSdJwt(bundle, privateKey);

    // 5. Sign the SD-JWT
    const sdJwt = new SDJwt(
        await new jose.SignJWT(packedPayload)
            .setProtectedHeader({ alg: 'ES256' })
            .sign(privateKey),
        disclosures
    );

    const outputDir = join(process.cwd(), 'public', 'data');
    try { mkdirSync(outputDir, { recursive: true }); } catch (e) { }

    console.log(`Writing artifacts to ${outputDir}...`);

    writeFileSync(join(outputDir, 'sdjwt.txt'), sdJwt.toString());
    writeFileSync(join(outputDir, 'payload.json'), JSON.stringify(packedPayload, null, 2));
    writeFileSync(join(outputDir, 'disclosures.json'), JSON.stringify(disclosures.map(d => ({
        digest: d.digestValue,
        encoded: d.encoded,
        value: d.value,
        salt: d.salt
    })), null, 2));
    writeFileSync(join(outputDir, 'issuer_public.jwk.json'), JSON.stringify(publicJwk, null, 2));
    writeFileSync(join(outputDir, 'issuer_private.jwk.json'), JSON.stringify(privateJwk, null, 2));

    console.log("Generated complex FHIR Bundle SD-JWT artifacts in public/data/");
}

generate().catch(console.error);
