import { SDJwt } from "../../core/src/sdJwt";
import { SDPacker } from "../../core/src/issuer";
import { SignJWT } from "jose";
import { Verifier } from "../../core/src/verifier";
import fhirIndex from "../defs/fhir-r4-index.json" with { type: "json" };

type IndexElement = {
  path: string;
  min: number;
  max: string;
  repeating: boolean;
  types: { code: string; profiles?: string[] }[];
  isModifier?: boolean;
  isSummary?: boolean;
};

type IndexSD = {
  kind: string;
  url?: string;
  elements: IndexElement[];
};

type Index = {
  sourceUrl: string;
  generatedAt: string;
  structures: Record<string, IndexSD>;
};

const cachedIndex: Promise<Index> = Promise.resolve(fhirIndex as Index);

async function loadIndex(): Promise<Index> {
  return cachedIndex;
}

// Selective disclosure rules:
// - primitives and complex datatypes: conceal as a leaf (true), no recursion.
// - arrays: per-element configs (each element is a leaf unless it is a resource).
// - resources: recurse into children (they are the only structures we unfold).
function buildConfigForValue(
  value: any,
  structures: Index["structures"],
): any {
  if (value === null || typeof value !== "object") return true; // primitive

  if (Array.isArray(value)) {
    return value.map((v) => {
      // Resource elements still recurse; everything else is a leaf
      if ((v as any)?.resourceType && structures[(v as any).resourceType]) {
        return {
          _self: true,
          ...buildResourceConfig(v, structures),
        };
      }
      // Bundle.entry elements: make the entry itself SD'able AND recurse into resource
      if (
        (v as any)?.resource &&
        (v as any).resource?.resourceType &&
        structures[(v as any).resource.resourceType]
      ) {
        return {
          _self: true,  // Make the entry itself redactable
          resource: buildResourceConfig((v as any).resource, structures),  // Still recurse into resource fields
        };
      }
      return true;
    });
  }

  // Direct resource
  if ((value as any).resourceType && structures[(value as any).resourceType]) {
    return buildResourceConfig(value, structures);
  }

  // Container with a resource property (e.g., Bundle.entry.resource)
  if (
    (value as any).resource &&
    (value as any).resource.resourceType &&
    structures[(value as any).resource.resourceType]
  ) {
    return {
      resource: buildResourceConfig((value as any).resource, structures),
    };
  }

  // Complex datatype leaf (do not recurse)
  if (typeof value === "object") {
    return true;
  }

  const cfg: any = {};
  for (const [k, v] of Object.entries(value)) {
    cfg[k] = buildConfigForValue(v, structures);
  }
  return cfg;
}

function buildResourceConfig(
  resource: any,
  structures: Index["structures"],
): any {
  const cfg: any = {};
  const resourceType = resource.resourceType;
  const structureDef = resourceType ? structures[resourceType] : undefined;

  for (const [key, val] of Object.entries(resource)) {
    // Always disclose resourceType and id
    if (key === "resourceType" || key === "id") {
      cfg[key] = undefined;
      continue;
    }

    // Check if this element is a modifier - if so, always disclose it
    if (structureDef) {
      const elementPath = `${resourceType}.${key}`;
      const element = structureDef.elements.find((el: any) => el.path === elementPath);
      if (element?.isModifier === true) {
        cfg[key] = undefined; // Always disclose modifier elements
        continue;
      }
    }

    cfg[key] = buildConfigForValue(val, structures);
  }
  return cfg;
}

export type PackFhirOptions = {
  alg?: string; // signing alg, default ES256
};

export async function packFhirSdJwt(
  payload: any,
  signingKey: any,
  opts: PackFhirOptions = {},
) {
  const { alg = "ES256" } = opts;
  const rootType = payload?.resourceType;
  if (!rootType) {
    throw new Error("FHIR payload must have resourceType");
  }
  const index = await loadIndex();
  const sd = index.structures[rootType];
  if (!sd) {
    throw new Error(`No StructureDefinition found for ${rootType}`);
  }

  const config = buildResourceConfig(payload, index.structures);
  const packer = new SDPacker();
  const { packedPayload, disclosures } = await packer.pack(payload, config ?? {});

  const jwt = await new SignJWT(packedPayload)
    .setProtectedHeader({ alg })
    .sign(signingKey);

  const sdJwt = new SDJwt(jwt, disclosures);
  return { sdJwt, jwt, disclosures, packedPayload };
}

/**
 * Helper to recursively remove empty arrays from an object
 */
function stripEmptyArrays(obj: any): any {
  if (Array.isArray(obj)) {
    const newArr = obj.map(stripEmptyArrays).filter(item => item !== undefined);
    return newArr.length > 0 ? newArr : undefined;
  }
  if (typeof obj === 'object' && obj !== null) {
    const newObj: any = {};
    for (const [key, val] of Object.entries(obj)) {
      const cleanVal = stripEmptyArrays(val);
      if (cleanVal !== undefined) {
        newObj[key] = cleanVal;
      }
    }
    return newObj;
  }
  return obj;
}

/**
 * Verify an SD-JWT string and return the verified FHIR payload
 * with empty arrays stripped.
 */
export async function verifyFhirSdJwt(
  sdJwtString: string,
  publicKey: any,
): Promise<any> {
  const parsed = await SDJwt.parse(sdJwtString);
  const verifier = new Verifier();
  const verified = await verifier.verify(parsed, publicKey);

  // Strip empty arrays from the verified result
  return stripEmptyArrays(verified);
}
