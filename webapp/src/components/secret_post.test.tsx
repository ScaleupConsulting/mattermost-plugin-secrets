import {screen, waitFor} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import React from 'react';

import type {Post} from '@mattermost/types/posts';

import SecretPost from './secret_post';
import {channelId, encryptedFile, me, other, renderAs, testRecipient} from './test_utils';

import * as client from '../client';
import {encryptFor} from '../crypto';
import type {SecretManifest} from '../file_crypto';
import * as keys from '../keys';

jest.mock('../client', () => ({
    ...jest.requireActual('../client'),
    getEnvelope: jest.fn(),
    getFileChunk: jest.fn(),
    ackSecret: jest.fn(),
    getStatus: jest.fn(),
}));
jest.mock('../keys', () => ({ensureKeyPair: jest.fn()}));

const mocked = client as jest.Mocked<typeof client>;
const chunkSize = 1024;
const postId = 'p'.repeat(26);

/**
 * Builds a v2 secret post sent by `other` to `me`.
 * @param bytes - the file size the server reports
 * @returns the post
 */
function filePost(bytes: number): Post {
    return {
        id: postId,
        channel_id: channelId,
        user_id: other,
        type: 'custom_secret',
        props: {secret_v: 2, secret_recipients: [me], secret_file_bytes: bytes},
    } as unknown as Post;
}

/**
 * Prepares an encrypted file secret for `me` and wires the client mocks to serve it.
 * @param size - plaintext bytes
 * @param text - the manifest's text
 * @returns the plaintext and the stored chunks
 */
async function serveFileSecret(size: number, text = 'see attached') {
    const {pair, recipient} = await testRecipient(me);
    (keys.ensureKeyPair as jest.Mock).mockResolvedValue(pair);
    const plain = crypto.getRandomValues(new Uint8Array(size));
    const {chunks, file} = await encryptedFile(plain, '../../evil/report.pdf', chunkSize);
    const manifest: SecretManifest = {v: 2, text, file};
    mocked.getEnvelope.mockResolvedValue(await encryptFor(JSON.stringify(manifest), {userId: me, publicKey: recipient.public_key, kid: 'kid1'}, channelId, other, 2));
    mocked.getFileChunk.mockImplementation(async (_postId, i) => chunks[i].slice().buffer);
    mocked.ackSecret.mockResolvedValue();
    return {plain, chunks};
}

describe('SecretPost with a file', () => {
    test('before opening it shows only the size', async () => {
        await serveFileSecret(2500);
        renderAs(<SecretPost post={filePost(2500)}/>);
        expect(screen.getByText('Encrypted file, 2 KB')).toBeVisible();
        expect(screen.queryByText(/report/)).not.toBeInTheDocument();
        expect(mocked.getEnvelope).not.toHaveBeenCalled();
    });

    test('opening fetches every chunk, verifies it, then acks', async () => {
        await serveFileSecret(2500);
        renderAs(<SecretPost post={filePost(2500)}/>);
        await userEvent.click(screen.getByRole('button', {name: 'Open'}));
        expect(await screen.findByTestId('secret-file-name')).toHaveTextContent('report.pdf');
        expect(screen.getByTestId('secret-revealed')).toHaveTextContent('see attached');
        expect(screen.getByRole('button', {name: 'Save file'})).toBeVisible();
        expect(mocked.getFileChunk.mock.calls.map(([, i]) => i)).toEqual([0, 1, 2]);
        await waitFor(() => expect(mocked.ackSecret).toHaveBeenCalledWith(postId));
    });

    // The send-a-secret website puts the visitor's text in the manifest as a PGP block, or '' when they typed none.
    const armored = '-----BEGIN PGP MESSAGE-----\n\nwcFMA1OaA4Fqk6ZvAQ/+Kp0=\n=AbCd\n-----END PGP MESSAGE-----\n';

    test('website-shaped text plus file offers Download for the text and Save file for the file', async () => {
        await serveFileSecret(2500, armored);
        const saved: Blob[] = [];
        URL.createObjectURL = jest.fn((blob: Blob) => {
            saved.push(blob);
            return 'blob:x';
        });
        URL.revokeObjectURL = jest.fn();
        const click = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
        renderAs(<SecretPost post={filePost(2500)}/>);
        await userEvent.click(screen.getByRole('button', {name: 'Open'}));
        expect(await screen.findByRole('button', {name: 'Save file'})).toBeVisible();
        expect(screen.getByTestId('secret-revealed')).toHaveTextContent('BEGIN PGP MESSAGE');
        await userEvent.click(screen.getByRole('button', {name: 'Download'}));
        const reader = new FileReader();
        const read = new Promise((resolve) => {
            reader.onload = () => resolve(reader.result);
        });
        reader.readAsText(saved[0]);
        expect(await read).toBe(armored);
        click.mockRestore();
    });

    test('website-shaped file with no text offers only Save file', async () => {
        await serveFileSecret(2500, '');
        renderAs(<SecretPost post={filePost(2500)}/>);
        await userEvent.click(screen.getByRole('button', {name: 'Open'}));
        expect(await screen.findByRole('button', {name: 'Save file'})).toBeVisible();
        expect(screen.queryByTestId('secret-revealed')).not.toBeInTheDocument();
        expect(screen.queryByRole('button', {name: 'Download'})).not.toBeInTheDocument();
    });

    test('a tampered chunk shows an error and does not ack', async () => {
        const {chunks} = await serveFileSecret(2500);
        chunks[1][3] ^= 1;
        renderAs(<SecretPost post={filePost(2500)}/>);
        await userEvent.click(screen.getByRole('button', {name: 'Open'}));
        expect(await screen.findByRole('alert')).toHaveTextContent('could not be decrypted');
        expect(mocked.ackSecret).not.toHaveBeenCalled();
    });

    test('a chunk that is already gone shows burned and does not ack', async () => {
        await serveFileSecret(2500);
        mocked.getFileChunk.mockRejectedValueOnce(new client.ApiError('gone', 410));
        renderAs(<SecretPost post={filePost(2500)}/>);
        await userEvent.click(screen.getByRole('button', {name: 'Open'}));
        expect(await screen.findByTestId('secret-burned')).toBeVisible();
        expect(mocked.ackSecret).not.toHaveBeenCalled();
    });

    test('the sender sees the size and read status', async () => {
        mocked.getStatus.mockResolvedValue({burned: false, remaining: [me], expires_at: 0});
        renderAs(<SecretPost post={filePost(5 * 1024 * 1024)}/>, other);
        expect(await screen.findByText(/Unread by 1 of 1/)).toBeVisible();
        expect(screen.getByText('Encrypted file, 5.0 MB')).toBeVisible();
    });
});

describe('SecretPost with text only', () => {
    test('reveal decrypts a v1 envelope and acks', async () => {
        const {pair, recipient} = await testRecipient(me);
        (keys.ensureKeyPair as jest.Mock).mockResolvedValue(pair);
        mocked.getEnvelope.mockResolvedValue(await encryptFor('hunter2', {userId: me, publicKey: recipient.public_key, kid: 'kid1'}, channelId, other));
        mocked.ackSecret.mockResolvedValue();
        const post = {...filePost(0), props: {secret_v: 1, secret_recipients: [me]}} as unknown as Post;
        renderAs(<SecretPost post={post}/>);
        expect(screen.queryByTestId('secret-file-size')).not.toBeInTheDocument();
        await userEvent.click(screen.getByRole('button', {name: 'Reveal'}));
        expect(await screen.findByTestId('secret-revealed')).toHaveTextContent('hunter2');
        await waitFor(() => expect(mocked.ackSecret).toHaveBeenCalledWith(postId));
        expect(mocked.getFileChunk).not.toHaveBeenCalled();
    });
});
