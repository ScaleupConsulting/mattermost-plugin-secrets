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
 * @returns the parsed JSON body
 */
async function doFetch<T>(path: string, options: Options = {}): Promise<T> {
    const response = await fetch(`${basePath}/plugins/${manifest.id}/api/v1${path}`, Client4.getOptions(options));
    const body = await response.json().catch(() => null);
    if (!response.ok) {
        throw new ApiError(body?.error ?? `Request failed with status ${response.status}`, response.status);
    }
    return body as T;
}

export type KeyRecord = {public_key: string; kid: string};
export type Recipient = {user_id: string; username: string; public_key: string; kid: string};
export type Recipients = {recipients: Recipient[]; missing: string[]; expiry_minutes: number};
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
 * @returns the new post ID
 */
export function createSecret(channelId: string, rootId: string, envelopes: Record<string, Envelope>): Promise<{post_id: string}> {
    return doFetch('/secrets', {method: 'post', body: JSON.stringify({channel_id: channelId, root_id: rootId, envelopes})});
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
