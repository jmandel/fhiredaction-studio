const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function toBase64(bytes: Uint8Array): string {
  let output = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const byte1 = bytes[i];
    const byte2 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const byte3 = i + 2 < bytes.length ? bytes[i + 2] : 0;

    const triplet = (byte1 << 16) | (byte2 << 8) | byte3;

    output += BASE64_ALPHABET[(triplet >> 18) & 0x3f];
    output += BASE64_ALPHABET[(triplet >> 12) & 0x3f];
    output += i + 1 < bytes.length ? BASE64_ALPHABET[(triplet >> 6) & 0x3f] : "=";
    output += i + 2 < bytes.length ? BASE64_ALPHABET[triplet & 0x3f] : "=";
  }
  return output;
}

function fromBase64(input: string): Uint8Array {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/.test(input)) {
    throw new Error("Invalid base64 input");
  }
  const length =
    Math.floor((input.length / 4) * 3) -
    (input.endsWith("==") ? 2 : input.endsWith("=") ? 1 : 0);
  const bytes = new Uint8Array(length);

  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (const char of input) {
    if (char === "=") break;
    buffer = (buffer << 6) | BASE64_ALPHABET.indexOf(char);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes[index++] = (buffer >> bits) & 0xff;
    }
  }
  return bytes;
}

export function base64UrlEncode(input: Uint8Array | string): string {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlDecode(input: string): Uint8Array {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  return fromBase64(padded);
}

export function base64UrlDecodeToString(input: string): string {
  const bytes = base64UrlDecode(input);
  return new TextDecoder().decode(bytes);
}

const HASH_ALG_MAP: Record<string, string> = {
  sha1: "SHA-1",
  "sha-1": "SHA-1",
  sha224: "SHA-224",
  "sha-224": "SHA-224",
  sha256: "SHA-256",
  "sha-256": "SHA-256",
  sha384: "SHA-384",
  "sha-384": "SHA-384",
  sha512: "SHA-512",
  "sha-512": "SHA-512",
  "sha-512/224": "SHA-512/224",
  "sha-512-224": "SHA-512/224",
  sha512224: "SHA-512/224",
  "sha-512/256": "SHA-512/256",
  "sha-512-256": "SHA-512/256",
  sha512256: "SHA-512/256",
  "sha3-256": "SHA3-256",
  "sha3-384": "SHA3-384",
  "sha3-512": "SHA3-512",
};

export function normalizeHashAlgorithm(input?: string): string {
  const key = (input || "SHA-256").toLowerCase();
  const normalized = HASH_ALG_MAP[key] || HASH_ALG_MAP[key.replace(/[^a-z0-9]/gi, "")];
  if (!normalized) {
    throw new Error(`Unsupported hash algorithm: ${input}`);
  }
  return normalized;
}

export function hashAlgClaimValue(webCryptoAlg: string): string {
  // Convert "SHA-256" -> "sha-256" for the spec-facing claim value
  return webCryptoAlg.toLowerCase();
}

export async function digest(
  data: string,
  algorithm: string = "SHA-256"
): Promise<string> {
  // The digest MUST be taken over the US-ASCII bytes of the base64url-encoded value that is the Disclosure.
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashAlg = normalizeHashAlgorithm(algorithm);

  try {
    const hashBuffer = await crypto.subtle.digest(hashAlg, dataBuffer);
    return base64UrlEncode(new Uint8Array(hashBuffer));
  } catch (err) {
    // Fallback to Node-style hashing where available to cover algorithms
    // not implemented in WebCrypto (e.g., SHA-224, SHA3 variants).
    /*
    try {
      // Dynamic import to keep browser bundles lean.
      const { createHash } = await import("crypto");
      // OpenSSL prefers dash separators for these algorithm names.
      const nodeAlg =
        hashAlg === "SHA-512/256"
          ? "sha512-256"
          : hashAlg === "SHA-512/224"
          ? "sha512-224"
          : hashAlg.toLowerCase();
      const hash = createHash(nodeAlg).update(dataBuffer).digest();
      return base64UrlEncode(new Uint8Array(hash));
    } catch (fallbackErr) {
      const message =
        (fallbackErr as Error)?.message || (err as Error)?.message || "Unknown error";
      throw new Error(`Hash algorithm ${hashAlg} not supported in this runtime: ${message}`);
    }
    */
    throw new Error(`Hash algorithm ${hashAlg} not supported in this runtime: ${(err as Error)?.message}`);
  }
}

export function generateSalt(lengthBytes: number = 16): string {
  const randomValues = new Uint8Array(lengthBytes);
  crypto.getRandomValues(randomValues);
  return base64UrlEncode(randomValues);
}
