import { mkdir, readFile, writeFile } from "fs/promises";
import { existsSync } from "fs";
import path from "path";
import { $ } from "bun";

type SDEntry = {
  resource?: {
    resourceType?: string;
    kind?: string;
    name?: string;
    url?: string;
    snapshot?: { element?: ElementDef[] };
  };
};

type ElementDef = {
  id?: string;
  path?: string;
  min?: number;
  max?: string;
  type?: { code?: string; profile?: string[] }[];
  isModifier?: boolean;
  isSummary?: boolean;
};

type OutElement = {
  path: string;
  min: number;
  max: string;
  repeating: boolean;
  types: { code: string; profiles?: string[] }[];
  isModifier?: boolean;
  isSummary?: boolean;
};

const FHIR_URL = "https://hl7.org/fhir/R4/definitions.json.zip";
const ROOT_DIR = process.cwd();
const CACHE_DIR = path.join(ROOT_DIR, "fhir", ".cache");
const ZIP_PATH = path.join(CACHE_DIR, "definitions.json.zip");
const EXTRACT_TARGETS = ["profiles-resources.json", "profiles-types.json"];
const OUT_INDEX = path.join(ROOT_DIR, "fhir", "defs", "fhir-r4-index.json");

async function ensureCache() {
  await mkdir(CACHE_DIR, { recursive: true });
  if (!existsSync(ZIP_PATH)) {
    console.log("Downloading FHIR R4 definitions...");
    await $`curl -L ${FHIR_URL} -o ${ZIP_PATH}`;
  } else {
    console.log("Using cached definitions.zip");
  }
  console.log("Extracting definitions...");
  await $`unzip -o ${ZIP_PATH} -d ${CACHE_DIR}`;
}

async function loadSDs(fileName: string) {
  const full = path.join(CACHE_DIR, fileName);
  const contents = await readFile(full, "utf8");
  const parsed = JSON.parse(contents);
  const entries: SDEntry[] = parsed.entry ?? [];
  return entries
    .map((e) => e.resource)
    .filter((r) => r?.resourceType === "StructureDefinition");
}

function toOutElement(el: ElementDef): OutElement | null {
  if (!el.path) return null;
  const pathStr = el.path;
  const min = typeof el.min === "number" ? el.min : 0;
  const max = typeof el.max === "string" ? el.max : "1";
  const repeating = max !== "1";
  const types =
    el.type?.map((t) => ({
      code: t.code ?? "",
      profiles: t.profile ?? undefined,
    })) ?? [];
  return {
    path: pathStr,
    min,
    max,
    repeating,
    types,
    isModifier: el.isModifier,
    isSummary: el.isSummary,
  };
}

function collect(structures: any[]) {
  const out: Record<string, { kind: string; url?: string; elements: OutElement[] }> = {};
  for (const sd of structures) {
    if (!sd.name || !sd.kind) continue;
    const elements: OutElement[] = [];
    for (const el of sd.snapshot?.element ?? []) {
      const outEl = toOutElement(el);
      if (outEl) elements.push(outEl);
    }
    out[sd.name] = {
      kind: sd.kind,
      url: sd.url,
      elements,
    };
  }
  return out;
}

async function main() {
  await ensureCache();
  const resources = await loadSDs("profiles-resources.json");
  const types = await loadSDs("profiles-types.json");
  const structures = {
    ...collect(resources),
    ...collect(types),
  };
  const payload = {
    sourceUrl: FHIR_URL,
    generatedAt: new Date().toISOString(),
    structures,
  };
  await mkdir(path.dirname(OUT_INDEX), { recursive: true });
  await writeFile(OUT_INDEX, JSON.stringify(payload, null, 2), "utf8");
  console.log(
    `Wrote structure index for ${Object.keys(structures).length} StructureDefinitions to ${OUT_INDEX}`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
