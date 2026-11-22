// ECIES for one recipient: ephemeral ECDH P-256, HKDF-SHA256, AES-256-GCM, all via WebCrypto.

export type Envelope = {kid: string; epk: string; iv: string; ct: string};

/** Envelope format: 1 carries the secret text, 2 a JSON manifest that may describe a file. */
export type EnvelopeVersion = 1 | 2;

const curve = {name: 'ECDH', namedCurve: 'P-256'};
const info = new TextEncoder().encode('mm-secrets-v1');

/**
 * Encodes bytes as standard base64 for JSON transport.
 * @param buf - bytes to encode
 * @returns base64 text
 */
export function toB64(buf: ArrayBuffer | Uint8Array): string {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = '';
    bytes.forEach((b) => {
        s += String.fromCharCode(b);
    });
    return btoa(s);
}

/**
 * Decodes standard base64 into bytes.
 * @param b64 - base64 text
 * @returns decoded bytes
 */
export function fromB64(b64: string): Uint8Array {
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/**
 * Builds the associated data that binds a ciphertext to its channel, sender and recipient.
 * It exists so the server cannot move an envelope to another post or person undetected.
 * @param channelId - the DM or group DM
 * @param senderId - the user who sent the secret
 * @param recipientId - the user the envelope is for
 * @param version - envelope format, so a v2 manifest can never be read as v1 text or back
 * @returns AES-GCM additional data
 */
function aad(channelId: string, senderId: string, recipientId: string, version: EnvelopeVersion): Uint8Array {
    return new TextEncoder().encode(`v${version}|${channelId}|${senderId}|${recipientId}`);
}

/**
 * Derives the AES-GCM key from an ECDH shared secret, salted with the ephemeral public key.
 * @param priv - our ECDH private key
 * @param pub - the other side's ECDH public key
 * @param epkRaw - the ephemeral public key bytes
 * @param usage - encrypt for senders, decrypt for recipients
 * @returns a non-extractable AES-256-GCM key
 */
async function deriveAesKey(priv: CryptoKey, pub: CryptoKey, epkRaw: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
    const bits = await crypto.subtle.deriveBits({name: 'ECDH', public: pub}, priv, 256);
    const hkdf = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        {name: 'HKDF', hash: 'SHA-256', salt: epkRaw, info},
        hkdf,
        {name: 'AES-GCM', length: 256},
        false,
        [usage],
    );
}

/**
 * Generates this browser's long-term key pair; the private key can never be exported.
 * @returns the new key pair
 */
export function generateKeyPair(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey(curve, false, ['deriveBits']) as Promise<CryptoKeyPair>;
}

/**
 * Exports a public key as base64 SPKI, the form the plugin server stores.
 * @param pub - the public key
 * @returns base64 SPKI
 */
export async function exportPublicKey(pub: CryptoKey): Promise<string> {
    return toB64(await crypto.subtle.exportKey('spki', pub));
}

/**
 * Encrypts plaintext for one recipient's registered public key.
 * @param plaintext - the secret
 * @param recipient - the recipient's user ID, base64 SPKI key and key ID
 * @param recipient.userId - recipient user ID
 * @param recipient.publicKey - base64 SPKI
 * @param recipient.kid - key ID as registered on the server
 * @param channelId - the channel the secret is posted in
 * @param senderId - the sending user's ID
 * @param version - envelope format; 2 for a file manifest
 * @returns the envelope to upload
 */
export async function encryptFor(
    plaintext: string,
    recipient: {userId: string; publicKey: string; kid: string},
    channelId: string,
    senderId: string,
    version: EnvelopeVersion = 1,
): Promise<Envelope> {
    const pub = await crypto.subtle.importKey('spki', fromB64(recipient.publicKey), curve, false, []);
    const eph = await crypto.subtle.generateKey(curve, true, ['deriveBits']) as CryptoKeyPair;
    const epkRaw = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
    const key = await deriveAesKey(eph.privateKey, pub, epkRaw, 'encrypt');
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
        {name: 'AES-GCM', iv, additionalData: aad(channelId, senderId, recipient.userId, version)},
        key,
        new TextEncoder().encode(plaintext),
    );
    return {kid: recipient.kid, epk: toB64(epkRaw), iv: toB64(iv), ct: toB64(ct)};
}

/**
 * Decrypts our envelope with this browser's private key.
 * @param env - the envelope fetched from the server
 * @param priv - our non-extractable private key
 * @param channelId - the post's channel
 * @param senderId - the post's author
 * @param recipientId - our user ID
 * @param version - envelope format from the post's secret_v
 * @returns the plaintext secret
 */
export async function decryptEnvelope(
    env: Envelope,
    priv: CryptoKey,
    channelId: string,
    senderId: string,
    recipientId: string,
    version: EnvelopeVersion = 1,
): Promise<string> {
    const epkRaw = fromB64(env.epk);
    const epk = await crypto.subtle.importKey('raw', epkRaw, curve, false, []);
    const key = await deriveAesKey(priv, epk, epkRaw, 'decrypt');
    const pt = await crypto.subtle.decrypt(
        {name: 'AES-GCM', iv: fromB64(env.iv), additionalData: aad(channelId, senderId, recipientId, version)},
        key,
        fromB64(env.ct),
    );
    return new TextDecoder().decode(pt);
}
