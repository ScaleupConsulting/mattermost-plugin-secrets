import {act, screen, waitFor} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import React from 'react';

import SecretModal from './secret_modal';
import {channelId, me, other, renderAs, testRecipient, uploadId} from './test_utils';

import * as client from '../client';
import {decryptEnvelope} from '../crypto';
import type {Envelope} from '../crypto';
import {openComposer} from '../events';
import {decryptFile} from '../file_crypto';
import type {SecretManifest} from '../file_crypto';

jest.mock('../client', () => ({
    ...jest.requireActual('../client'),
    getRecipients: jest.fn(),
    createSecret: jest.fn(),
    createUpload: jest.fn(),
    putChunk: jest.fn(),
    deleteUpload: jest.fn(),
}));
jest.mock('../keys', () => ({ensureKeyPair: jest.fn(() => Promise.resolve({}))}));

const mocked = client as jest.Mocked<typeof client>;
const chunkSize = 1024;

/**
 * Renders the modal, opens it for the test DM and waits for recipients to load.
 * @param overrides - fields to change in the recipients response
 * @returns the recipient's key pair
 */
async function openModal(overrides: Partial<client.Recipients> = {}) {
    const {pair, recipient} = await testRecipient(other);
    mocked.getRecipients.mockResolvedValue({
        recipients: [recipient],
        missing: [],
        expiry_minutes: 10080,
        file_secrets_enabled: true,
        max_file_bytes: 10 * chunkSize,
        ...overrides,
    });
    renderAs(<SecretModal/>);
    act(() => openComposer({channelId, rootId: '', text: ''}));
    await screen.findByText('To: @bob');
    return pair;
}

beforeEach(() => {
    mocked.createSecret.mockResolvedValue({post_id: 'p'.repeat(26)});
    mocked.createUpload.mockResolvedValue({upload_id: uploadId, chunk_size: chunkSize, max_chunks: 10, expires_at: 0});
    mocked.putChunk.mockResolvedValue();
    mocked.deleteUpload.mockResolvedValue();
});

describe('SecretModal', () => {
    test('a text-only secret stays a v1 envelope and opens no upload', async () => {
        const pair = await openModal();
        await userEvent.type(screen.getByRole('textbox', {name: 'Secret text'}), 'hunter2');
        await userEvent.click(screen.getByRole('button', {name: 'Send secret'}));
        await waitFor(() => expect(mocked.createSecret).toHaveBeenCalled());
        const [, , envelopes, file] = mocked.createSecret.mock.calls[0];
        expect(file).toBeUndefined();
        expect(mocked.createUpload).not.toHaveBeenCalled();
        expect(await decryptEnvelope(envelopes[other], pair.privateKey, channelId, me, other)).toBe('hunter2');
    });

    test('a file is encrypted in chunks and described only inside the v2 envelope', async () => {
        const pair = await openModal();
        const plain = crypto.getRandomValues(new Uint8Array((2 * chunkSize) + 452));
        await userEvent.upload(screen.getByLabelText('Attach a file (optional)'), new File([plain], 'plans.pdf', {type: 'application/pdf'}));
        expect(screen.getByRole('button', {name: 'Send secret'})).toBeEnabled();
        await userEvent.click(screen.getByRole('button', {name: 'Send secret'}));
        await waitFor(() => expect(mocked.createSecret).toHaveBeenCalled());

        expect(mocked.createUpload).toHaveBeenCalledWith(channelId, plain.length);
        const stored = mocked.putChunk.mock.calls.map(([id, i, ct]) => {
            expect(id).toBe(uploadId);
            return [i, ct] as const;
        });
        expect(stored.map(([i, ct]) => [i, ct.length])).toEqual([[0, chunkSize + 16], [1, chunkSize + 16], [2, 452 + 16]]);
        const [, , envelopes, file] = mocked.createSecret.mock.calls[0];
        expect(file).toEqual({upload_id: uploadId, chunks: 3, bytes: plain.length});
        expect(JSON.stringify(mocked.createSecret.mock.calls[0])).not.toContain('plans.pdf');

        const manifest = JSON.parse(await decryptEnvelope(envelopes[other] as Envelope, pair.privateKey, channelId, me, other, 2)) as SecretManifest;
        expect(manifest.file).toMatchObject({name: 'plans.pdf', type: 'application/pdf', size: plain.length, chunks: 3});
        const out = await decryptFile(manifest.file, async (i) => stored[i][1].slice().buffer);
        expect(new Uint8Array(await out.arrayBuffer())).toEqual(plain);
        expect(mocked.deleteUpload).not.toHaveBeenCalled();
    });

    test('a file over the limit cannot be sent', async () => {
        await openModal();
        await userEvent.upload(screen.getByLabelText('Attach a file (optional)'), new File([new Uint8Array((10 * chunkSize) + 1)], 'big.bin'));
        expect(screen.getByText('This file is larger than 10 KB.')).toBeVisible();
        expect(screen.getByRole('button', {name: 'Send secret'})).toBeDisabled();
    });

    test('the file picker is hidden when this user may not send files', async () => {
        await openModal({file_secrets_enabled: false});
        expect(screen.queryByLabelText('Attach a file (optional)')).not.toBeInTheDocument();
    });

    test('a failed chunk upload cancels the upload and sends nothing', async () => {
        await openModal();
        mocked.putChunk.mockResolvedValueOnce().mockRejectedValueOnce(new Error('network down'));
        await userEvent.upload(screen.getByLabelText('Attach a file (optional)'), new File([new Uint8Array(3 * chunkSize)], 'a.bin'));
        await userEvent.click(screen.getByRole('button', {name: 'Send secret'}));
        expect(await screen.findByRole('alert')).toHaveTextContent('network down');
        expect(mocked.deleteUpload).toHaveBeenCalledWith(uploadId);
        expect(mocked.createSecret).not.toHaveBeenCalled();
    });

    test('upload progress is announced', async () => {
        await openModal();
        let release: () => void = () => undefined;
        mocked.putChunk.mockResolvedValueOnce().mockImplementationOnce(() => new Promise<void>((resolve) => {
            release = resolve;
        }));
        await userEvent.upload(screen.getByLabelText('Attach a file (optional)'), new File([new Uint8Array(2 * chunkSize)], 'a.bin'));
        await userEvent.click(screen.getByRole('button', {name: 'Send secret'}));
        expect(await screen.findByText('Encrypting and uploading the file: 50%')).toBeVisible();
        expect(screen.getByRole('status')).toHaveAttribute('aria-live', 'polite');
        act(() => release());
        await waitFor(() => expect(mocked.createSecret).toHaveBeenCalled());
    });
});
