// File secrets: one random AES-256-GCM key per file, chunked STREAM-style so no chunk can be
// reordered, dropped, moved to another upload or appended after the last one undetected.

import {fromB64, toB64} from './crypto';

/** What a v2 envelope tells a recipient about the attached file; only ever stored encrypted. */
export type FileManifest = {
    upload_id: string;
    name: string;
    type: string;
    size: number;
    chunk_size: number;
    chunks: number;
    key: string;
    np: string;
};

/** The plaintext of a v2 envelope. */
export type SecretManifest = {v: 2; text: string; file: FileManifest};

/** A file's content key with its raw bytes for the manifest. */
export type FileKey = {key: CryptoKey; raw: Uint8Array; np: Uint8Array};

const noncePrefixBytes = 7;

/**
 * Generates a fresh content key and nonce prefix for one file.
 * @returns the key, its raw bytes and the 7-byte nonce prefix
 */
export async function generateFileKey(): Promise<FileKey> {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
    return {key, raw, np: crypto.getRandomValues(new Uint8Array(noncePrefixBytes))};
}

/**
 * Builds a chunk nonce: prefix, big-endian index, then 1 on the last chunk and 0 otherwise.
 * @param np - the file's nonce prefix
 * @param index - the chunk index
 * @param isLast - whether this is the final chunk
 * @returns the 12-byte nonce
 */
function chunkNonce(np: Uint8Array, index: number, isLast: boolean): Uint8Array {
    const iv = new Uint8Array(12);
    iv.set(np, 0);
    new DataView(iv.buffer).setUint32(noncePrefixBytes, index, false);
    iv[11] = isLast ? 1 : 0;
    return iv;
}

/**
 * Binds a chunk to its upload and position.
 * @param uploadId - the server's upload ID
 * @param index - the chunk index
 * @returns AES-GCM additional data
 */
function chunkAad(uploadId: string, index: number): Uint8Array {
    return new TextEncoder().encode(`mm-secrets-file-v2|${uploadId}|${index}`);
}

/**
 * Number of chunks a file of this size splits into.
 * @param size - plaintext bytes, at least 1
 * @param chunkSize - plaintext bytes per chunk
 * @returns the chunk count
 */
export function chunkCount(size: number, chunkSize: number): number {
    return Math.ceil(size / chunkSize);
}

/**
 * Encrypts one chunk.
 * @param fk - the file key
 * @param uploadId - the server's upload ID
 * @param index - the chunk index
 * @param isLast - whether this is the final chunk
 * @param plain - the plaintext bytes
 * @returns ciphertext with its 16-byte tag
 */
export async function encryptChunk(fk: FileKey, uploadId: string, index: number, isLast: boolean, plain: Uint8Array): Promise<Uint8Array> {
    const ct = await crypto.subtle.encrypt(
        {name: 'AES-GCM', iv: chunkNonce(fk.np, index, isLast), additionalData: chunkAad(uploadId, index)},
        fk.key,
        plain,
    );
    return new Uint8Array(ct);
}

/**
 * Encrypts a file chunk by chunk and hands each chunk to put, reading the next one while the last uploads.
 * @param file - the file to send
 * @param uploadId - the server's upload ID
 * @param chunkSize - plaintext bytes per chunk, chosen by the server
 * @param fk - the file key
 * @param put - uploads one encrypted chunk
 * @param onProgress - called after each chunk is uploaded
 * @returns the number of chunks
 */
export async function encryptFile(
    file: Blob,
    uploadId: string,
    chunkSize: number,
    fk: FileKey,
    put: (index: number, ct: Uint8Array) => Promise<void>,
    onProgress?: (done: number, total: number) => void,
): Promise<number> {
    const total = chunkCount(file.size, chunkSize);
    const encrypt = async (i: number) => {
        const plain = new Uint8Array(await file.slice(i * chunkSize, Math.min(file.size, (i + 1) * chunkSize)).arrayBuffer());
        return encryptChunk(fk, uploadId, i, i === total - 1, plain);
    };
    let next = encrypt(0);
    for (let i = 0; i < total; i++) {
        // eslint-disable-next-line no-await-in-loop
        const ct = await next;
        if (i + 1 < total) {
            next = encrypt(i + 1);
            next.catch(() => undefined); // surfaced by the await on the next turn
        }
        // eslint-disable-next-line no-await-in-loop
        await put(i, ct);
        onProgress?.(i + 1, total);
    }
    return total;
}

/**
 * Checks a decrypted manifest's file description before any chunk is fetched.
 * @param m - the file description
 */
function checkManifest(m: FileManifest) {
    const ok = typeof m.upload_id === 'string' && Number.isSafeInteger(m.size) && m.size > 0 &&
        Number.isSafeInteger(m.chunk_size) && m.chunk_size > 0 && m.chunks === chunkCount(m.size, m.chunk_size) &&
        fromB64(m.key).length === 32 && fromB64(m.np).length === noncePrefixBytes;
    if (!ok) {
        throw new Error('The file description in this secret is invalid.');
    }
}

/**
 * Fetches and decrypts every chunk, prefetching the next while decrypting, and checks the result is complete.
 * @param m - the file description from the decrypted manifest
 * @param fetchChunk - downloads one encrypted chunk
 * @param onProgress - called after each chunk is decrypted
 * @returns the plaintext file
 */
export async function decryptFile(
    m: FileManifest,
    fetchChunk: (index: number) => Promise<ArrayBuffer>,
    onProgress?: (done: number, total: number) => void,
): Promise<Blob> {
    checkManifest(m);
    const key = await crypto.subtle.importKey('raw', fromB64(m.key), 'AES-GCM', false, ['decrypt']);
    const np = fromB64(m.np);
    const parts: Uint8Array[] = [];
    let total = 0;
    let next = fetchChunk(0);
    for (let i = 0; i < m.chunks; i++) {
        // eslint-disable-next-line no-await-in-loop
        const ct = await next;
        if (i + 1 < m.chunks) {
            next = fetchChunk(i + 1);
            next.catch(() => undefined); // surfaced by the await on the next turn
        }
        const isLast = i === m.chunks - 1;
        // eslint-disable-next-line no-await-in-loop
        const plain = new Uint8Array(await crypto.subtle.decrypt(
            {name: 'AES-GCM', iv: chunkNonce(np, i, isLast), additionalData: chunkAad(m.upload_id, i)},
            key,
            ct,
        ));
        if (!isLast && plain.length !== m.chunk_size) {
            throw new Error('The file is corrupted.');
        }
        total += plain.length;
        parts.push(plain);
        onProgress?.(i + 1, m.chunks);
    }
    if (total !== m.size) {
        throw new Error('The file is incomplete.');
    }
    return new Blob(parts, {type: 'application/octet-stream'});
}

/**
 * Describes a file for its manifest once its chunks are uploaded.
 * @param file - the sent file
 * @param uploadId - the server's upload ID
 * @param chunkSize - plaintext bytes per chunk
 * @param fk - the file key
 * @returns the manifest's file part
 */
export function describeFile(file: File, uploadId: string, chunkSize: number, fk: FileKey): FileManifest {
    return {
        upload_id: uploadId,
        name: file.name.slice(0, 200),
        type: file.type.slice(0, 100),
        size: file.size,
        chunk_size: chunkSize,
        chunks: chunkCount(file.size, chunkSize),
        key: toB64(fk.raw),
        np: toB64(fk.np),
    };
}

/**
 * Makes a sender-chosen file name safe to save: no path parts, control characters or leading dots.
 * @param name - the name from the manifest
 * @returns a safe file name
 */
export function safeFileName(name: string): string {
    // eslint-disable-next-line no-control-regex
    const base = (name.split(/[/\\]/).pop() ?? '').replace(/[\u0000-\u001f\u007f<>:"|?*]/g, '_').replace(/^[.\s]+/, '').trim().slice(0, 200);
    return base || 'secret-file';
}
