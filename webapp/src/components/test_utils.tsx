import {render} from '@testing-library/react';
import React from 'react';
import {IntlProvider} from 'react-intl';
import {Provider} from 'react-redux';
import {createStore} from 'redux';

import {exportPublicKey, generateKeyPair} from '../crypto';
import {encryptFile, describeFile, generateFileKey} from '../file_crypto';
import type {FileManifest} from '../file_crypto';

export const me = 'm'.repeat(26);
export const other = 'o'.repeat(26);
export const channelId = 'c'.repeat(26);
export const uploadId = 'u'.repeat(26);

/**
 * Renders a component as the given user inside a real Redux store and IntlProvider.
 * @param ui - the element to render
 * @param userId - the current user
 * @returns the render result
 */
export function renderAs(ui: React.ReactElement, userId = me) {
    const store = createStore(() => ({entities: {users: {currentUserId: userId}}}));
    return render(
        <Provider store={store}>
            <IntlProvider locale='en'>{ui}</IntlProvider>
        </Provider>,
    );
}

/**
 * Generates a key pair and its registered form for a test recipient.
 * @param userId - the recipient
 * @returns the pair and the recipient record the server would return
 */
export async function testRecipient(userId: string) {
    const pair = await generateKeyPair();
    return {pair, recipient: {user_id: userId, username: 'bob', public_key: await exportPublicKey(pair.publicKey), kid: 'kid1'}};
}

/**
 * Encrypts bytes as a file secret, returning the stored chunks and the manifest's file part.
 * @param plain - the file content
 * @param name - the file name
 * @param chunkSize - plaintext bytes per chunk
 * @returns the chunks and file manifest
 */
export async function encryptedFile(plain: Uint8Array, name: string, chunkSize: number): Promise<{chunks: Uint8Array[]; file: FileManifest}> {
    const f = new File([plain], name);
    const fk = await generateFileKey();
    const chunks: Uint8Array[] = [];
    await encryptFile(f, uploadId, chunkSize, fk, async (i, ct) => {
        chunks[i] = ct;
    });
    return {chunks, file: describeFile(f, uploadId, chunkSize, fk)};
}
