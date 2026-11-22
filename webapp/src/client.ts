import manifest from 'manifest';

import type {Options} from '@mattermost/types/client4';

import {Client4} from 'mattermost-redux/client';

import type {Envelope} from './crypto';

let basePath = '';

/**
 * Keeps only the path of the SiteURL so requests stay same-origin under any hostname.
 * @param siteURL - the server's configured SiteURL
 */
export function setSiteURL(siteURL: string | undefined) {
    basePath = siteURL ? new URL(siteURL).pathname.replace(/\/$/, '') : '';
}

/** An HTTP error from the plugin API carrying the server's message and status. */
export class ApiError extends Error {
    status: number;

    /**
     * @param message - the server's error text
     * @param status - the HTTP status
     */
    constructor(message: string, status: number) {
        super(message);
        this.status = status;
    }
}

/**
 * Calls the plugin API with the session's CSRF token, throwing ApiError on failure.
 * @param path - path under /api/v1
 * @param options - fetch options
 * @returns the response, known to be OK
 */
async function doRequest(path: string, options: Options = {}): Promise<Response> {
    const response = await fetch(`${basePath}/plugins/${manifest.id}/api/v1${path}`, Client4.getOptions(options));
    if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new ApiError(body?.error ?? `Request failed with status ${response.status}`, response.status);
    }
    return response;
}

/**
 * Calls the plugin API and parses its JSON reply.
 * @param path - path under /api/v1
 * @param options - fetch options
 * @returns the parsed JSON body
 */
async function doFetch<T>(path: string, options: Options = {}): Promise<T> {
    const response = await doRequest(path, options);
    return response.json().catch(() => null) as Promise<T>;
}

export type KeyRecord = {public_key: string; kid: string};
export type Recipient = {user_id: string; username: string; public_key: string; kid: string};
export type Recipients = {
    recipients: Recipient[];
    missing: string[];
    expiry_minutes: number;
    file_secrets_enabled: boolean;
    max_file_bytes: number;
};
export type Upload = {upload_id: string; chunk_size: number; max_chunks: number; expires_at: number};
export type FileAttachment = {upload_id: string; chunks: number; bytes: number};
export type SecretStatus = {burned: boolean; remaining: string[] | null; expires_at: number};

/**
 * Fetches the caller's registered public key, or null if none.
 * @returns the key record or null
 */
export async function getMyKey(): Promise<KeyRecord | null> {
    try {
        return await doFetch<KeyRecord>('/keys/me');
    } catch (e) {
        if (e instanceof ApiError && e.status === 404) {
            return null;
        }
        throw e;
    }
}

/**
 * Registers this browser's public key for the caller.
 * @param publicKey - base64 SPKI
 * @returns the stored record
 */
export function registerKey(publicKey: string): Promise<KeyRecord> {
    return doFetch('/keys', {method: 'post', body: JSON.stringify({public_key: publicKey})});
}

/**
 * Lists a DM or group DM's other members with their keys.
 * @param channelId - the channel
 * @returns recipients, usernames without a key, and the expiry
 */
export function getRecipients(channelId: string): Promise<Recipients> {
    return doFetch(`/channels/${channelId}/recipients`);
}

/**
 * Uploads per-recipient ciphertext; the server posts the placeholder.
 * @param channelId - the channel
 * @param rootId - thread root, or empty
 * @param envelopes - ciphertext keyed by recipient user ID
 * @param file - a completed upload to attach, if any
 * @returns the new post ID
 */
export function createSecret(channelId: string, rootId: string, envelopes: Record<string, Envelope>, file?: FileAttachment): Promise<{post_id: string}> {
    return doFetch('/secrets', {method: 'post', body: JSON.stringify({channel_id: channelId, root_id: rootId, envelopes, file})});
}

/**
 * Opens an upload session for an encrypted file.
 * @param channelId - the channel the secret will be posted in
 * @param maxBytes - the file's plaintext size
 * @returns the upload ID and the chunk size to use
 */
export function createUpload(channelId: string, maxBytes: number): Promise<Upload> {
    return doFetch('/uploads', {method: 'post', body: JSON.stringify({channel_id: channelId, max_bytes: maxBytes})});
}

/**
 * Uploads one encrypted chunk; sending the same index again replaces it.
 * @param uploadId - the upload session
 * @param index - the chunk index
 * @param ct - the encrypted chunk
 */
export async function putChunk(uploadId: string, index: number, ct: Uint8Array): Promise<void> {
    await doRequest(`/uploads/${uploadId}/chunks/${index}`, {method: 'put', body: ct, headers: {'Content-Type': 'application/octet-stream'}});
}

/**
 * Cancels an unfinished upload so the server deletes its chunks.
 * @param uploadId - the upload session
 */
export async function deleteUpload(uploadId: string): Promise<void> {
    await doRequest(`/uploads/${uploadId}`, {method: 'delete'});
}

/**
 * Downloads one encrypted chunk of a file secret.
 * @param postId - the secret post
 * @param index - the chunk index
 * @returns the encrypted bytes
 */
export async function getFileChunk(postId: string, index: number): Promise<ArrayBuffer> {
    const response = await doRequest(`/secrets/${postId}/file/${index}`);
    return response.arrayBuffer();
}

/**
 * Fetches the caller's ciphertext for a secret post.
 * @param postId - the secret post
 * @returns the envelope
 */
export function getEnvelope(postId: string): Promise<Envelope> {
    return doFetch(`/secrets/${postId}/envelope`);
}

/**
 * Tells the server the caller has read the secret so it deletes their ciphertext.
 * @param postId - the secret post
 */
export async function ackSecret(postId: string): Promise<void> {
    await doFetch(`/secrets/${postId}/ack`, {method: 'post', body: '{}'});
}

/**
 * Reads which recipients still have not read a secret.
 * @param postId - the secret post
 * @returns the status
 */
export function getStatus(postId: string): Promise<SecretStatus> {
    return doFetch(`/secrets/${postId}/status`);
}
