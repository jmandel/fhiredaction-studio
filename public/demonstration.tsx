import React, { useState, useEffect, useCallback, useRef } from 'react';
import { createRoot } from 'react-dom/client';
import { SDJwt, SD_KEY, ARRAY_ELEMENT_KEY, DIGEST_ALG_KEY } from '../core/src/sdJwt';
import { verifyFhirSdJwt, packFhirSdJwt } from '../fhir/src/autoSdJwt';
import { Disclosure } from '../core/src/disclosure';
import { normalizeHashAlgorithm } from '../core/src/common';
import * as jose from 'jose';

// Static demo artifacts (bundled at build time / served statically)
import sdJwtTextRaw from './data/sdjwt.txt' with { type: 'text' };
import issuerPublicJwk from './data/issuer_public.jwk.json' with { type: 'json' };
import issuerPrivateJwk from './data/issuer_private.jwk.json' with { type: 'json' };
import disclosureRows from './data/disclosures.json' with { type: 'json' };
import markerCursorImg from './marker-cursor.png';

type DisclosureFileRow = {
    encoded: string;
    digest?: string;
    key?: string;
};

// --- Styles & Assets ---

const markerCursor = `url('${markerCursorImg}') 0 109, auto`;

// --- Styles Update ---
const styles = {
    container: {
        display: 'flex',
        flexDirection: 'column' as const,
        height: '100vh',
        backgroundColor: '#fdfbf7',
        fontFamily: "'Patrick Hand', cursive",
        color: '#2c3e50',
        overflow: 'hidden', // Prevent body scroll
    },
    header: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        position: 'relative' as const,
        textAlign: 'center' as const,
        padding: '20px',
        fontSize: '2.5em',
        color: '#333',
        textTransform: 'uppercase' as const,
        letterSpacing: '2px',
        borderBottom: '4px solid #333',
        flexShrink: 0,
        background: '#fff',
        zIndex: 10,
    },
    mainContent: {
        display: 'flex',
        flexDirection: 'row' as const,
        flex: 1,
        overflow: 'hidden',
    },
    pane: {
        flex: 1,
        minWidth: '450px',
        padding: '10px',
        overflowY: 'auto' as const,
        borderRight: '2px dashed #ccc',
        display: 'flex',
        flexDirection: 'column' as const,
        cursor: markerCursor,
    },
    rightPane: {
        flex: 1,
        minWidth: '450px',
        padding: '30px',
        overflowY: 'auto' as const,
        background: '#f4f4f4',
    },
    copyButton: {
        background: '#2980b9',
        color: 'white',
        border: 'none',
        padding: '8px 16px',
        fontSize: '0.9em',
        cursor: 'pointer',
        fontFamily: "'Patrick Hand', cursive",
        borderRadius: '4px',
        marginLeft: '10px',
        boxShadow: '2px 2px 4px rgba(0,0,0,0.2)',
        transition: 'background 0.2s',
    },
    gearButton: {
        position: 'absolute' as const,
        right: '16px',
        top: '50%',
        transform: 'translateY(-50%)',
        background: 'none',
        border: 'none',
        fontSize: '1.4em',
        cursor: 'pointer',
        padding: '6px',
        lineHeight: 1,
    },
    sectionHeader: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '10px',
    },
    intro: {
        fontSize: '0.9em',
        marginBottom: '8px',
        textAlign: 'center' as const,
    },
    card: {
        backgroundColor: '#fff',
        boxShadow: '5px 5px 15px rgba(0,0,0,0.1)',
        padding: '8px',
        marginBottom: '10px',
        border: '2px solid #333',
        position: 'relative' as const,
    },
    jsonContainer: {
        fontSize: '0.9em',
        lineHeight: '1.2',
        userSelect: 'none' as const,
        cursor: markerCursor,
    },
    // ... keep other styles (key, value, bracket, cutPoint, etc.)
    key: { color: '#e67e22', fontWeight: 'bold' as const, cursor: markerCursor },
    value: { color: '#2980b9', cursor: markerCursor },
    bracket: { color: '#7f8c8d', fontWeight: 'bold' as const, cursor: markerCursor },
    cutPoint: {
        position: 'relative' as const,
        border: '2px dashed rgba(0,0,0,0.15)',
        borderRadius: '4px',
        margin: '1px',
        padding: '2px 4px',
        transition: 'background 0.2s, border-color 0.2s',
        cursor: markerCursor,
    },
    markerOverlay: {
        position: 'absolute' as const,
        top: 0, left: 0, right: 0, bottom: 0,
        pointerEvents: 'none' as const,
        zIndex: 10,
        overflow: 'hidden',
    },
    modalOverlay: {
        position: 'fixed' as const,
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.5)',
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        zIndex: 1000,
    },
    modalContent: {
        backgroundColor: '#fff',
        padding: '30px',
        borderRadius: '8px',
        maxWidth: '600px',
        width: '90%',
        maxHeight: '80vh',
        overflow: 'auto' as const,
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.3)',
    },
    modalHeader: {
        fontSize: '1.5em',
        fontWeight: 'bold' as const,
        marginBottom: '20px',
        paddingBottom: '10px',
        borderBottom: '2px solid #3498db',
    },
    modalSection: {
        marginBottom: '30px',
    },
    textarea: {
        width: '100%',
        minHeight: '120px',
        padding: '10px',
        fontFamily: 'monospace',
        fontSize: '0.9em',
        border: '1px solid #bdc3c7',
        borderRadius: '4px',
        resize: 'vertical' as const,
        boxSizing: 'border-box' as const,
    },
    button: {
        padding: '10px 20px',
        fontSize: '0.9em',
        border: 'none',
        borderRadius: '4px',
        backgroundColor: '#3498db',
        color: '#fff',
        cursor: 'pointer',
        marginRight: '10px',
        transition: 'background 0.2s',
    },
    errorText: {
        color: '#e74c3c',
        fontSize: '0.85em',
        marginTop: '10px',
        padding: '8px',
        backgroundColor: '#fadbd8',
        borderRadius: '4px',
        border: '1px solid #e74c3c',
    }
};

// --- Data loading helpers ---

async function parseDisclosuresFromFile(rows: DisclosureFileRow[], hashAlg: string): Promise<Disclosure[]> {
    const normalizedAlg = normalizeHashAlgorithm(hashAlg);
    return Promise.all(
        rows.map(async (row) => {
            const parsed = await Disclosure.parse(row.encoded);
            // Always re-hash using the algorithm advertised in the JWT payload.
            await parsed.calculateDigest(normalizedAlg);
            return parsed;
        })
    );
}

// --- Helper: Derive Public Key from Private Key ---

async function derivePublicKey(privateJwk: any): Promise<any> {
    // Strip private fields from the supplied JWK and ensure an alg is present.
    const { d, p, q, dp, dq, qi, oth, k, ...publicOnly } = privateJwk as any;
    const alg = privateJwk.alg || (privateJwk.kty === 'EC' ? 'ES256' : 'RS256');
    return { ...publicOnly, alg };
}

// --- Helper: Pack Custom FHIR Content ---

async function packCustomFhir(fhirJson: string, privateJwk: any): Promise<{
    sdJwt: SDJwt;
    hashAlg: string;
    publicKey: any;
}> {
    // Parse FHIR JSON
    const fhirResource = JSON.parse(fhirJson);

    // Determine algorithm from key
    const alg = privateJwk.alg || (privateJwk.kty === 'EC' ? 'ES256' : 'RS256');

    // Import private key
    const privateKey = await jose.importJWK(privateJwk, alg);

    // Pack FHIR resource into SD-JWT
    const { sdJwt } = await packFhirSdJwt(fhirResource, privateKey, { alg });

    // Derive public key
    const publicKey = await derivePublicKey(privateJwk);

    // Get hash algorithm from SD-JWT
    const jwtPayload = jose.decodeJwt(sdJwt.jwt);
    const hashAlg = normalizeHashAlgorithm((jwtPayload as any)[DIGEST_ALG_KEY] as string | undefined);

    return { sdJwt, hashAlg, publicKey };
}

async function safeParseSdJwt(raw: string): Promise<SDJwt> {
    try {
        return await SDJwt.parse(raw);
    } catch (e) {
        // Fallback for inputs that contain only the issuer JWS (no disclosures/tilde separators).
        const jwtOnly = raw.split('~')[0];
        return new SDJwt(jwtOnly, []);
    }
}

async function loadArtifacts() {
    const sdJwtText = sdJwtTextRaw.trim();
    const jwtPart = sdJwtText.split('~')[0];
    const payload = jose.decodeJwt(jwtPart);
    const hashAlg = normalizeHashAlgorithm((payload as any)[DIGEST_ALG_KEY] as string | undefined);

    const parsedSdJwt = await safeParseSdJwt(sdJwtText);

    const loadedDisclosures = disclosureRows
        ? await parseDisclosuresFromFile(disclosureRows as DisclosureFileRow[], hashAlg)
        : parsedSdJwt.disclosures;

    if (loadedDisclosures.length === 0) {
        throw new Error('No disclosures found in sdjwt.txt or data/disclosures.json');
    }

    // Ensure digests match the advertised algorithm.
    await Promise.all(loadedDisclosures.map((d) => d.calculateDigest(hashAlg)));

    const hydratedSdJwt = new SDJwt(parsedSdJwt.jwt, loadedDisclosures, parsedSdJwt.kbJwt);

    return { sdJwt: hydratedSdJwt, hashAlg, issuerKey: issuerPublicJwk, issuerPrivateKey: issuerPrivateJwk };
}

// --- Helper: Trace Disclosures ---

type TraceResult = {
    payload: any;
    pathMap: Map<string, string>; // Path -> Digest
};

async function traceDisclosures(sdJwt: SDJwt, hashAlgHint?: string): Promise<TraceResult> {
    const jwtPayload = jose.decodeJwt(sdJwt.jwt);
    const digestMap = new Map<string, Disclosure>();

    const alg = normalizeHashAlgorithm(
        ((jwtPayload as any)[DIGEST_ALG_KEY] as string | undefined) || hashAlgHint || 'SHA-256'
    );

    for (const d of sdJwt.disclosures) {
        await d.calculateDigest(alg);
        if (d.digestValue) {
            digestMap.set(d.digestValue, d);
        }
    }

    const pathMap = new Map<string, string>();

    const traverse = (input: any, path: string[]): any => {
        if (typeof input !== 'object' || input === null) {
            return input;
        }

        if (Array.isArray(input)) {
            const result: any[] = [];
            input.forEach((item, index) => {
                if (typeof item === 'object' && item !== null && ARRAY_ELEMENT_KEY in item) {
                    const digest = item[ARRAY_ELEMENT_KEY];
                    if (typeof digest === 'string' && digestMap.has(digest)) {
                        const disclosure = digestMap.get(digest)!;
                        const currentPath = [...path, index.toString()].join('.');

                        // Record the cut point
                        pathMap.set(currentPath, digest);

                        // Recursively traverse the disclosed value
                        result.push(traverse(disclosure.value, [...path, index.toString()]));
                    }
                } else {
                    result.push(traverse(item, [...path, index.toString()]));
                }
            });
            return result;
        }

        // Object
        const result: any = {};
        const sdDigests = input[SD_KEY];

        // Copy plain properties
        for (const [key, value] of Object.entries(input)) {
            if (key === SD_KEY || key === DIGEST_ALG_KEY) continue;
            result[key] = traverse(value, [...path, key]);
        }

        // Apply disclosures
        if (Array.isArray(sdDigests)) {
            for (const digest of sdDigests) {
                if (typeof digest === 'string' && digestMap.has(digest)) {
                    const disclosure = digestMap.get(digest)!;
                    const key = disclosure.key!;
                    const currentPath = [...path, key].join('.');

                    // Record cut point
                    pathMap.set(currentPath, digest);

                    result[key] = traverse(disclosure.value, [...path, key]);
                }
            }
        }

        return result;
    };

    const reconstructed = traverse(jwtPayload, []);
    // Cleanup root control claims
    delete reconstructed._sd;
    delete reconstructed._sd_alg;

    return { payload: reconstructed, pathMap };
}

// --- Marker SVG Component ---

const MarkerStroke = ({ width, height, seed }: { width: number, height: number, seed: number }) => {
    // Generate a somewhat random but consistent path based on dimensions
    const yMid = height / 2;
    const wobble = 3;

    // Simple jagged line simulation
    let d = `M 0 ${yMid}`;
    for (let x = 0; x <= width; x += 10) {
        const y = yMid + (Math.sin(x * 0.1 + seed) * wobble) + (Math.random() - 0.5) * 2;
        d += ` L ${x} ${y}`;
    }

    // Add a second pass for thickness/texture
    d += ` M 0 ${yMid + 2}`;
    for (let x = 0; x <= width; x += 12) {
        const y = yMid + 2 + (Math.cos(x * 0.15 + seed) * wobble);
        d += ` L ${x} ${y}`;
    }

    return (
        <svg width="100%" height="100%" viewBox={`0 0 ${width} ${height}`} style={styles.markerOverlay}>
            <path d={d} stroke="black" strokeWidth="4" fill="none" strokeLinecap="round" opacity="0.85" />
        </svg>
    );
};

// --- Recursive JSON Node Component ---

const JsonNode = ({
    data,
    path,
    pathMap,
    redactedDigests,
    ancestorRedacted,
    onToggle,
    isDragging,
    onMouseEnter
}: {
    data: any,
    path: string[],
    pathMap: Map<string, string>,
    redactedDigests: Set<string>,
    ancestorRedacted: boolean,
    onToggle: (digests: string[]) => void,
    isDragging: boolean,
    onMouseEnter: (digest: string) => void
}) => {
    const pathKey = path.join('.');
    const ownDigest = pathMap.get(pathKey);
    const isCutPoint = !!ownDigest;
    const isRedacted = ancestorRedacted || (ownDigest ? redactedDigests.has(ownDigest) : false);
    const isObject = typeof data === 'object' && data !== null;
    const isArray = Array.isArray(data);

    // Ref for measuring dimensions for the marker stroke
    const nodeRef = useRef<HTMLSpanElement>(null);
    const [dimensions, setDimensions] = useState({ width: 0, height: 0 });

    useEffect(() => {
        if (isRedacted && nodeRef.current) {
            setDimensions({
                width: nodeRef.current.offsetWidth,
                height: nodeRef.current.offsetHeight
            });
        }
    }, [isRedacted, data]); // Re-measure if data changes or redaction state changes

    const handleMouseDown = (e: React.MouseEvent) => {
        // Prevent native drag behavior so we can track mouseover for our custom drag
        e.preventDefault();
        if (ownDigest) {
            e.stopPropagation();
            onToggle([ownDigest]);
        }
    };

    const handleMouseEnter = (e: React.MouseEvent) => {
        if (ownDigest) {
            e.stopPropagation();
            if (isDragging) {
                onMouseEnter(ownDigest);
            }
        }
    };

    const handleKeyClick = (e: React.MouseEvent, key: string, val: any) => {
        const childPath = [...path, key];
        const childPathKey = childPath.join('.');
        const childDigest = pathMap.get(childPathKey);

        if (childDigest) {
            e.stopPropagation();
            onToggle([childDigest]);
        } else if (Array.isArray(val)) {
            // If value is array, try to toggle all immediate children that have digests
            const digestsToToggle: string[] = [];
            val.forEach((_, idx) => {
                const itemPath = [...childPath, idx.toString()].join('.');
                const itemDigest = pathMap.get(itemPath);
                if (itemDigest) {
                    digestsToToggle.push(itemDigest);
                }
            });
            if (digestsToToggle.length > 0) {
                e.stopPropagation();
                onToggle(digestsToToggle);
            }
        }
    };

    const containerStyle = {
        ...styles.cutPoint,
        borderColor: isCutPoint ? 'rgba(0,0,0,0.2)' : 'transparent',
        background: isCutPoint ? 'rgba(255,255,255,0.5)' : 'transparent',
        display: isObject ? 'block' : 'inline-block',
        opacity: isRedacted ? 0.6 : 1,
    } as const;

    // Render content
    let content;
    if (!isObject) {
        content = <span style={styles.value}>{JSON.stringify(data)}</span>;
    } else {
        const entries: any[] = isArray ? data : Object.entries(data);
        content = (
            <>
                <span style={styles.bracket}>{isArray ? '[' : '{'}</span>
                <div style={{ marginLeft: 8 }}>
                    {isArray
                        ? entries.map((val: any, idx: number) => (
                            <div key={idx}>
                                <JsonNode
                                    data={val}
                                    path={[...path, idx.toString()]}
                                    pathMap={pathMap}
                                    redactedDigests={redactedDigests}
                                    ancestorRedacted={isRedacted}
                                    onToggle={onToggle}
                                    isDragging={isDragging}
                                    onMouseEnter={onMouseEnter}
                                />
                                {idx < entries.length - 1 && <span style={styles.bracket}>,</span>}
                            </div>
                        ))
                        : (entries as [string, any][]).map(([key, val], idx) => (
                            <div key={key}>
                                <span
                                    style={{ ...styles.key, cursor: markerCursor }}
                                    onClick={(e) => handleKeyClick(e, key, val)}
                                >
                                    "{key}":
                                </span>
                                <JsonNode
                                    data={val}
                                    path={[...path, key]}
                                    pathMap={pathMap}
                                    redactedDigests={redactedDigests}
                                    ancestorRedacted={isRedacted}
                                    onToggle={onToggle}
                                    isDragging={isDragging}
                                    onMouseEnter={onMouseEnter}
                                />
                                {idx < (entries as any).length - 1 && <span style={styles.bracket}>,</span>}
                            </div>
                        ))
                    }
                </div>
                <span style={styles.bracket}>{isArray ? ']' : '}'}</span>
            </>
        );
    }

    return (
        <span
            ref={nodeRef}
            data-path={pathKey}
            style={containerStyle}
            onMouseDown={handleMouseDown}
            onMouseEnter={handleMouseEnter}
        >
            {content}
            {isRedacted && ownDigest && (
                <MarkerStroke width={dimensions.width} height={dimensions.height} seed={pathKey.length} />
            )}
        </span>
    );
};


// --- Main App Component ---

// --- Helper: Calculate Reachable Digests ---

function calculateReachableDigests(
    payload: any,
    pathMap: Map<string, string>,
    redactedDigests: Set<string>
): Set<string> {
    const reachable = new Set<string>();

    const traverse = (data: any, path: string[]) => {
        const pathKey = path.join('.');
        const digest = pathMap.get(pathKey);

        // If this node is redacted, stop traversal (don't include this digest or descendants)
        if (digest && redactedDigests.has(digest)) {
            return;
        }

        // If this node has a digest and is NOT redacted, include it
        if (digest) {
            reachable.add(digest);
        }

        if (typeof data === 'object' && data !== null) {
            if (Array.isArray(data)) {
                data.forEach((item, idx) => traverse(item, [...path, idx.toString()]));
            } else {
                Object.entries(data).forEach(([key, val]) => traverse(val, [...path, key]));
            }
        }
    };

    traverse(payload, []);
    return reachable;
}

// --- Copy Button Component ---

const CopyButton = ({ text, label }: { text: string, label?: string }) => {
    const [copied, setCopied] = useState(false);

    const handleCopy = async () => {
        try {
            await navigator.clipboard.writeText(text);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch (err) {
            console.error('Failed to copy:', err);
        }
    };

    return (
        <button
            onClick={handleCopy}
            style={{
                ...styles.copyButton,
                background: copied ? '#27ae60' : '#2980b9',
            }}
        >
            {copied ? '✓ Copied!' : label || 'Copy'}
        </button>
    );
};

// --- Settings Modal Component ---

const SettingsModal = ({
    isOpen,
    onClose,
    onGenerateFhir,
    onUpdateKey,
    onResetFhir,
    onResetKey
}: {
    isOpen: boolean;
    onClose: () => void;
    onGenerateFhir: (fhirJson: string) => Promise<void>;
    onUpdateKey: (privateKeyJwk: string) => Promise<void>;
    onResetFhir: () => void;
    onResetKey: () => void;
}) => {
    const [fhirInput, setFhirInput] = useState('');
    const [keyInput, setKeyInput] = useState('');
    const [fhirError, setFhirError] = useState('');
    const [keyError, setKeyError] = useState('');

    if (!isOpen) return null;

    const handleGenerateFhir = async () => {
        setFhirError('');
        try {
            await onGenerateFhir(fhirInput);
            setFhirInput('');
        } catch (e: any) {
            setFhirError(e.message || 'Failed to generate SD-JWT');
        }
    };

    const handleUpdateKey = async () => {
        setKeyError('');
        try {
            await onUpdateKey(keyInput);
            setKeyInput('');
        } catch (e: any) {
            setKeyError(e.message || 'Failed to update key');
        }
    };

    const handleResetFhirClick = async () => {
        setFhirError('');
        try {
            await onResetFhir();
            setFhirInput('');
        } catch (e: any) {
            setFhirError(e.message || 'Failed to reset');
        }
    };

    return (
        <div style={styles.modalOverlay} onClick={onClose}>
            <div style={styles.modalContent} onClick={(e) => e.stopPropagation()}>
                <div style={styles.modalHeader}>
                    ⚙️ Settings
                    <button onClick={onClose} style={{ ...styles.button, float: 'right' as const }}>Close</button>
                </div>

                <div style={styles.modalSection}>
                    <h3>Custom FHIR Content</h3>
                    <p>Paste any valid FHIR resource (Bundle, Patient, etc.):</p>
                    <textarea
                        style={styles.textarea}
                        value={fhirInput}
                        onChange={(e) => setFhirInput(e.target.value)}
                        placeholder='{"resourceType": "Patient", "id": "example", ...}'
                    />
                    {fhirError && <div style={styles.errorText}>{fhirError}</div>}
                    <div style={{ marginTop: '10px' }}>
                        <button style={styles.button} onClick={handleGenerateFhir}>Generate SD-JWT</button>
                        <button style={{ ...styles.button, backgroundColor: '#e74c3c' }} onClick={handleResetFhirClick}>Reset to Default</button>
                    </div>
                </div>

                <div style={styles.modalSection}>
                    <h3>Custom Private Key</h3>
                    <p>Paste a JWK private key (ES256, RS256, etc.):</p>
                    <textarea
                        style={styles.textarea}
                        value={keyInput}
                        onChange={(e) => setKeyInput(e.target.value)}
                        placeholder='{"kty": "EC", "crv": "P-256", "d": "...", ...}'
                    />
                    {keyError && <div style={styles.errorText}>{keyError}</div>}
                    <div style={{ marginTop: '10px' }}>
                        <button style={styles.button} onClick={handleUpdateKey}>Update Key</button>
                        <button style={{ ...styles.button, backgroundColor: '#e74c3c' }} onClick={onResetKey}>Reset Key</button>
                    </div>
                </div>
            </div>
        </div>
    );
};

// --- Main App Component ---

const App = () => {
    const [sdJwt, setSdJwt] = useState<SDJwt | null>(null);
    const [fullPayload, setFullPayload] = useState<any | null>(null);
    const [pathMap, setPathMap] = useState<Map<string, string>>(new Map());
    const [redactedDigests, setRedactedDigests] = useState<Set<string>>(new Set());

    // Output state
    const [output, setOutput] = useState<{
        artifact: string;
        raw: { jwtPayload: any, disclosures: string[] };
        verification: any;
        cleanFhir: any;
    } | null>(null);

    const [issuerKey, setIssuerKey] = useState<any>(null);
    const [hashAlg, setHashAlg] = useState<string>('SHA-256');
    const [loadError, setLoadError] = useState<string | null>(null);

    // Settings state
    const [settingsOpen, setSettingsOpen] = useState(false);
    const [customPrivateKey, setCustomPrivateKey] = useState<any | null>(null);
    const [defaultArtifacts, setDefaultArtifacts] = useState<{
        sdJwt: SDJwt;
        issuerKey: any;
        issuerPrivateKey: any;
        hashAlg: string;
    } | null>(null);

    // Interaction state
    const [isDragging, setIsDragging] = useState(false);

    useEffect(() => {
        async function load() {
            try {
                const { sdJwt: hydratedSdJwt, hashAlg, issuerKey, issuerPrivateKey } = await loadArtifacts();

                // Store defaults for reset
                setDefaultArtifacts({ sdJwt: hydratedSdJwt, issuerKey, issuerPrivateKey, hashAlg });

                setSdJwt(hydratedSdJwt);
                setIssuerKey(issuerKey);
                setHashAlg(hashAlg);

                const { payload, pathMap } = await traceDisclosures(hydratedSdJwt, hashAlg);
                setFullPayload(payload);
                setPathMap(pathMap);
            } catch (e) {
                console.error("Failed to load data", e);
                setLoadError((e as Error)?.message || 'Unknown error');
            }
        }
        load();
    }, []);

    // Settings handlers
    const handleGenerateFhir = useCallback(async (fhirJson: string) => {
        const privateKey = customPrivateKey || defaultArtifacts?.issuerPrivateKey;
        if (!privateKey) throw new Error('No private key available');

        const { sdJwt: newSdJwt, hashAlg: newHashAlg, publicKey } = await packCustomFhir(fhirJson, privateKey);

        setSdJwt(newSdJwt);
        setHashAlg(newHashAlg);
        setIssuerKey(publicKey);
        setRedactedDigests(new Set());

        const { payload, pathMap } = await traceDisclosures(newSdJwt, newHashAlg);
        setFullPayload(payload);
        setPathMap(pathMap);
    }, [customPrivateKey, defaultArtifacts]);

    const handleUpdateKey = useCallback(async (privateKeyJwk: string) => {
        const parsedKey = JSON.parse(privateKeyJwk);
        setCustomPrivateKey(parsedKey);

        const publicKey = await derivePublicKey(parsedKey);
        setIssuerKey(publicKey);
    }, []);

    const handleResetFhir = useCallback(async () => {
        if (!defaultArtifacts) return;

        setSdJwt(defaultArtifacts.sdJwt);
        setHashAlg(defaultArtifacts.hashAlg);
        setIssuerKey(customPrivateKey ? await derivePublicKey(customPrivateKey) : defaultArtifacts.issuerKey);
        setRedactedDigests(new Set());

        const { payload, pathMap } = await traceDisclosures(defaultArtifacts.sdJwt, defaultArtifacts.hashAlg);
        setFullPayload(payload);
        setPathMap(pathMap);
    }, [defaultArtifacts, customPrivateKey]);

    const handleResetKey = useCallback(async () => {
        if (!defaultArtifacts) return;

        setCustomPrivateKey(null);
        setIssuerKey(defaultArtifacts.issuerKey);
    }, [defaultArtifacts]);

    // Global mouse up to stop dragging
    useEffect(() => {
        const handleGlobalMouseUp = () => setIsDragging(false);
        window.addEventListener('mouseup', handleGlobalMouseUp);
        return () => window.removeEventListener('mouseup', handleGlobalMouseUp);
    }, []);

    const handleMouseDown = () => setIsDragging(true);

    const toggleRedaction = useCallback((digests: string[]) => {
        setRedactedDigests(prev => {
            const next = new Set(prev);
            // If any are not redacted, redact them all.
            // If all are redacted, un-redact them all.
            const allRedacted = digests.every(d => next.has(d));

            digests.forEach(d => {
                if (allRedacted) {
                    next.delete(d);
                } else {
                    next.add(d);
                }
            });
            return next;
        });
    }, []);

    const handleMouseEnterNode = useCallback((digest: string) => {
        setRedactedDigests(prev => {
            if (prev.has(digest)) return prev; // Don't toggle off while dragging, only add
            const next = new Set(prev);
            next.add(digest);
            return next;
        });
    }, []);

    // Auto-update output with debounce
    useEffect(() => {
        if (!sdJwt || !issuerKey || !fullPayload) return;

        const timer = setTimeout(async () => {
            const reachableDigests = calculateReachableDigests(fullPayload, pathMap, redactedDigests);
            const filteredDisclosures = sdJwt.disclosures.filter(d =>
                d.digestValue && reachableDigests.has(d.digestValue)
            );

            const newSdJwt = new SDJwt(sdJwt.jwt, filteredDisclosures);
            const presentationStr = newSdJwt.toString();

            // Single pass FHIR-aware verification (also strips empty arrays)
            const issuerAlg = (issuerKey as any)?.alg || 'ES256';
            const cleanFhir = await verifyFhirSdJwt(
                presentationStr,
                await jose.importJWK(issuerKey, issuerAlg)
            );

            setOutput({
                artifact: presentationStr,
                raw: {
                    jwtPayload: jose.decodeJwt(newSdJwt.jwt),
                    disclosures: filteredDisclosures.map(d => d.encoded)
                },
                verification: { verified: true, claimCount: Object.keys(cleanFhir ?? {}).length },
                cleanFhir
            });
        }, 300); // 300ms debounce

        return () => clearTimeout(timer);
    }, [redactedDigests, sdJwt, issuerKey, fullPayload, pathMap]);

    if (loadError) return <div style={{ color: 'red', padding: 20 }}>Failed to load demo data: {loadError}</div>;
    if (!fullPayload || !sdJwt) return <div style={{ padding: 20 }}>Loading...</div>;

    return (
        <div style={styles.container} onMouseDownCapture={handleMouseDown} data-layout="container">
            <div style={styles.header}>
                FHIRedaction Studio
                <button
                    onClick={() => setSettingsOpen(true)}
                    style={styles.gearButton}
                    title="Settings"
                >
                    ⚙️
                </button>
            </div>

            <div style={styles.mainContent} data-layout="main-content">
                {/* Left Pane: Interaction */}
                <div style={styles.pane} data-layout="left-pane">
                    <div style={styles.intro}>
                        <p>
                            You are the <strong>Holder</strong>.
                            Use your permanent marker to cross out (redact) any information you don't want to share.
                        </p>
                        <p style={{ fontSize: '0.9em', color: '#666' }}>
                            (Click or drag across dashed boxes to redact)
                        </p>
                    </div>

                    <div style={styles.card}>
                        <div style={styles.jsonContainer}>
                            <JsonNode
                                data={fullPayload}
                                path={[]}
                                pathMap={pathMap}
                                redactedDigests={redactedDigests}
                                ancestorRedacted={false}
                                onToggle={toggleRedaction}
                                isDragging={isDragging}
                                onMouseEnter={handleMouseEnterNode}
                            />
                        </div>
                    </div>
                </div>

                {/* Right Pane: Output */}
                <div style={styles.rightPane} data-layout="right-pane">
                    {output ? (
                        <div>
                            <div style={styles.sectionHeader}>
                                <h3 style={{ margin: 0 }}>1. Full SD-JWT Artifact</h3>
                                <CopyButton text={output.artifact} label="Copy Artifact" />
                            </div>
                            <div style={{ ...styles.card, background: '#fff', border: '1px dashed #999', wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '0.8em', maxHeight: '200px', overflowY: 'auto' }}>
                                {output.artifact}
                            </div>

                            <div style={styles.sectionHeader}>
                                <h3 style={{ margin: 0 }}>2. Raw Decoded Parts</h3>
                                <CopyButton text={JSON.stringify({ jwtPayload: output.raw.jwtPayload, disclosures: output.raw.disclosures }, null, 2)} label="Copy Raw" />
                            </div>
                            <div style={{ ...styles.card, background: '#fff', border: '1px dashed #999' }}>
                                <h4>JWT Payload</h4>
                                <pre style={{ margin: 0, overflowX: 'auto' }}>{JSON.stringify(output.raw.jwtPayload, null, 2)}</pre>
                                <h4>Disclosures ({output.raw.disclosures.length})</h4>
                                <pre style={{ margin: 0, overflowX: 'auto', maxHeight: '200px' }}>{JSON.stringify(output.raw.disclosures, null, 2)}</pre>
                            </div>

                            <div style={styles.sectionHeader}>
                                <h3 style={{ margin: 0 }}>3. Verification Status</h3>
                            </div>
                            <div style={{ ...styles.card, background: '#e8f8f5', border: '1px solid #27ae60', color: '#27ae60' }}>
                                <strong>✓ Signature Verified</strong>
                            </div>

                            <div style={styles.sectionHeader}>
                                <h3 style={{ margin: 0 }}>4. Final FHIR Output (Cleaned)</h3>
                                <CopyButton text={JSON.stringify(output.cleanFhir, null, 2)} label="Copy FHIR" />
                            </div>
                            <div style={{ ...styles.card, background: '#fff', border: '2px solid #2980b9' }}>
                                <pre style={{ margin: 0, overflowX: 'auto' }}>
                                    {JSON.stringify(output.cleanFhir, null, 2)}
                                </pre>
                            </div>
                        </div>
                    ) : (
                        <div style={{ textAlign: 'center', marginTop: 50, color: '#999' }}>
                            Generating output...
                        </div>
                    )}
                </div>
            </div>

            <SettingsModal
                isOpen={settingsOpen}
                onClose={() => setSettingsOpen(false)}
                onGenerateFhir={handleGenerateFhir}
                onUpdateKey={handleUpdateKey}
                onResetFhir={handleResetFhir}
                onResetKey={handleResetKey}
            />
        </div>
    );
};

const root = createRoot(document.getElementById('root')!);
root.render(<App />);
