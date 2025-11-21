import { describe, it, expect, beforeAll } from "bun:test";
import * as jose from "jose";
import { packFhirSdJwt } from "../src/autoSdJwt";
import { Verifier } from "../../src/verifier";
import { SDJwt } from "../../src/sdJwt";

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

    const { packedPayload, disclosures } = await packFhirSdJwt(bundle, privKey);

    expect(packedPayload.entry).toHaveLength(2);
    const patientResource = packedPayload.entry[0].resource as any;
    // Patient resource is selectively disclosable as a whole (name array elements are leaf cutpoints)
    expect(patientResource.name[0]["..."]).toBeDefined();

    const conditionResource = packedPayload.entry[1].resource as any;
    expect(conditionResource._sd).toBeDefined();
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

    const { packedPayload } = await packFhirSdJwt(bundle, privKey);
    const imm = packedPayload.entry[0].resource as any;
    expect(Array.isArray(imm._sd)).toBe(true);
    expect(imm._sd.length).toBeGreaterThanOrEqual(1);
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

    const { packedPayload, disclosures } = await packFhirSdJwt(bundle, privKey);

    const conditionResource = packedPayload.entry[0].resource as any;
    expect(conditionResource._sd).toBeDefined();
  });
});
