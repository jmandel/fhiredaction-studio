import { describe, it, expect, beforeAll } from "bun:test";
import * as jose from "jose";
import { packFhirSdJwt } from "../src/autoSdJwt";
import { Verifier } from "../../core/src/verifier";
import { SDJwt } from "../../core/src/sdJwt";

describe("FHIR auto SD-JWT", () => {
  let privKey: jose.KeyLike;
  let pubKey: jose.KeyLike;

  beforeAll(async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
    privKey = privateKey;
    pubKey = publicKey;
  });

  it("packs and verifies an Observation with optional and repeating elements concealed", async () => {
    const obs = {
      resourceType: "Observation",
      status: "final",
      code: { text: "Example" },
      valueString: "hidden note", // optional (min=0), should be concealed
      category: [
        { text: "a" },
        { text: "b" }, // repeating array, per-element concealment by default
      ],
    };

    const { sdJwt } = await packFhirSdJwt(obs, privKey, {
      concealOptional: true,
    });

    const verifier = new Verifier();
    const verified = await verifier.verify(sdJwt, pubKey);

    expect(verified.resourceType).toBe("Observation");
    expect(verified.valueString).toBe("hidden note");
    expect(Array.isArray(verified.category)).toBe(true);
    expect(verified.category.length).toBe(2);
    expect(verified._sd).toBeUndefined();
    expect(verified._sd_alg).toBeUndefined();
  });

  it("throws when resourceType is missing", async () => {
    await expect(
      // @ts-expect-error invalid payload, resourceType missing
      packFhirSdJwt({ status: "final" }, privKey),
    ).rejects.toThrow("FHIR payload must have resourceType");
  });

  it("conceals repeating Patient.name and telecom per element even inside a Bundle entry", async () => {
    const bundle = {
      resourceType: "Bundle" as const,
      type: "collection",
      entry: [
        {
          resource: {
            resourceType: "Patient",
            name: [
              { family: "Smart", given: ["Alice"] },
              { family: "Jones", given: ["Bob"] },
            ],
            telecom: [
              { system: "phone", value: "111-1111" },
              { system: "email", value: "a@example.com" },
            ],
          },
        },
        {
          resource: {
            resourceType: "Condition",
            code: { text: "Example condition" },
          },
        },
      ],
    };

    const { sdJwt, packedPayload } = await packFhirSdJwt(bundle, privKey);

    // Bundle entries are concealed at the entry level; resources appear only after disclosure.
    expect(packedPayload.entry).toHaveLength(2);
    expect(packedPayload.entry[0]["..."]).toBeDefined();
    expect(packedPayload.entry[1]["..."]).toBeDefined();

    // After verification, the Patient resource is intact and per-element name/telecom are present.
    const verifier = new Verifier();
    const verified = await verifier.verify(sdJwt, pubKey);
    const patient = verified.entry[0].resource;
    expect(Array.isArray(patient.name)).toBe(true);
    expect(patient.name).toHaveLength(2);
    expect(patient.telecom).toHaveLength(2);
  });

  it("does not pack Immunization as a single undisclosed blob", async () => {
    const bundle = {
      resourceType: "Bundle" as const,
      type: "collection",
      entry: [
        {
          resource: {
            resourceType: "Immunization",
            id: "i1",
            status: "completed",
            patient: { reference: "Patient/p1" },
            vaccineCode: {
              coding: [{ system: "http://hl7.org/fhir/sid/cvx", code: "207" }],
            },
            occurrenceDateTime: "2021-01-01",
          },
        },
      ],
    };

    const { sdJwt, packedPayload } = await packFhirSdJwt(bundle, privKey);
    // Entry is concealed as a unit.
    expect(packedPayload.entry[0]["..."]).toBeDefined();

    // Full Immunization content is recovered when disclosed/verified.
    const verifier = new Verifier();
    const verified = await verifier.verify(sdJwt, pubKey);
    const imm = verified.entry[0].resource;
    expect(imm.vaccineCode.coding[0].code).toBe("207");
    expect(imm.status).toBe("completed");
  });

  it("conceals required complex fields like clinicalStatus and subject on Condition", async () => {
    const bundle = {
      resourceType: "Bundle" as const,
      type: "collection",
      entry: [
        {
          resource: {
            resourceType: "Condition",
            id: "c1",
            clinicalStatus: { coding: [{ system: "x", code: "y" }] },
            subject: { reference: "Patient/p1" },
            code: { text: "foo" },
          },
        },
      ],
    };

    const { sdJwt, packedPayload } = await packFhirSdJwt(bundle, privKey);

    // Entry is concealed at entry level.
    expect(packedPayload.entry[0]["..."]).toBeDefined();

    // After disclosure, required complex fields are present.
    const verifier = new Verifier();
    const verified = await verifier.verify(sdJwt, pubKey);
    const condition = verified.entry[0].resource;
    expect(condition.clinicalStatus).toBeDefined();
    expect(condition.subject.reference).toBe("Patient/p1");
  });

  it("always discloses modifier elements while concealing non-modifiers", async () => {
    const allergy = {
      resourceType: "AllergyIntolerance" as const,
      clinicalStatus: { coding: [{ system: "x", code: "active" }] }, // modifier element
      code: { text: "Peanut" }, // non-modifier complex datatype (should be SD'able)
    };

    const { sdJwt, packedPayload, disclosures } = await packFhirSdJwt(allergy, privKey);

    // Modifier element stays in the issuer-signed payload unredacted
    expect(packedPayload.clinicalStatus).toBeDefined();
    // Non-modifier is concealed
    expect(packedPayload.code).toBeUndefined();
    expect(Array.isArray(packedPayload._sd)).toBe(true);
    expect(disclosures.some((d) => d.key === "code")).toBe(true);
    expect(disclosures.some((d) => d.key === "clinicalStatus")).toBe(false);

    // After verification, both are present
    const verifier = new Verifier();
    const verified = await verifier.verify(sdJwt, pubKey);
    expect(verified.clinicalStatus.coding[0].code).toBe("active");
    expect(verified.code.text).toBe("Peanut");
  });
});
