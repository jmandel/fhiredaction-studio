
export function base64UrlEncode(input: Uint8Array | string): string {
  let base64: string;
  if (typeof input === 'string') {
    base64 = btoa(input);
  } else {
    base64 = btoa(String.fromCharCode(...input));
  }
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(input: string): Uint8Array {
    // Add padding if necessary
    let padded = input;
    while (padded.length % 4 !== 0) {
        padded += '=';
    }
    const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

export function base64UrlDecodeToString(input: string): string {
    const bytes = base64UrlDecode(input);
    return new TextDecoder().decode(bytes);
}

export async function digest(data: string, algorithm: string = 'SHA-256'): Promise<string> {
    // The digest MUST be taken over the US-ASCII bytes of the base64url-encoded value that is the Disclosure.
    // Wait, the spec says:
    // "The digest MUST be taken over the US-ASCII bytes of the base64url-encoded value that is the Disclosure."
    // The Disclosure itself is a base64url encoded string of the JSON array.
    // So we are hashing the Disclosure string itself (which is ASCII).
    
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest(algorithm, dataBuffer);
    return base64UrlEncode(new Uint8Array(hashBuffer));
}

export function generateSalt(lengthBytes: number = 16): string {
    const randomValues = new Uint8Array(lengthBytes);
    crypto.getRandomValues(randomValues);
    return base64UrlEncode(randomValues);
}
