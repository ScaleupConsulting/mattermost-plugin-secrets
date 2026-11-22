import React, {useCallback, useEffect, useRef, useState} from 'react';
import {FormattedMessage, useIntl} from 'react-intl';
import {useSelector} from 'react-redux';

import type {GlobalState} from '@mattermost/types/store';

import {getCurrentUserId} from 'mattermost-redux/selectors/entities/users';

import {createSecret, createUpload, deleteUpload, getRecipients, putChunk} from '../client';
import type {FileAttachment, Recipients} from '../client';
import {encryptFor} from '../crypto';
import type {Envelope, EnvelopeVersion} from '../crypto';
import {openEvent} from '../events';
import type {OpenDetail} from '../events';
import {chunkCount, describeFile, encryptFile, generateFileKey} from '../file_crypto';
import type {SecretManifest} from '../file_crypto';
import {formatBytes} from '../format';
import {ensureKeyPair} from '../keys';

import './secret_modal.css';

const maxChars = 4000;

/** Thrown inside the upload loop once the sender cancels. */
class Cancelled extends Error {}

/**
 * Root-mounted modal that encrypts a secret, and optionally a file, in the browser for every recipient and uploads only ciphertext.
 * @returns the modal, or nothing while closed
 */
export default function SecretModal() {
    const intl = useIntl();
    const userId = useSelector((state: GlobalState) => getCurrentUserId(state));
    const [target, setTarget] = useState<OpenDetail | null>(null);
    const [text, setText] = useState('');
    const [file, setFile] = useState<File | null>(null);
    const [info, setInfo] = useState<Recipients | null>(null);
    const [error, setError] = useState('');
    const [busy, setBusy] = useState(false);
    const [progress, setProgress] = useState<{done: number; total: number} | null>(null);
    const cancelled = useRef(false);
    const fileInput = useRef<HTMLInputElement>(null);

    useEffect(() => {
        /**
         * Opens the modal for the channel named in the event and loads its recipients' keys.
         * @param e - the open event
         */
        const onOpen = (e: Event) => {
            const detail = (e as CustomEvent<OpenDetail>).detail;
            setTarget(detail);
            setText(detail.text);
            setFile(null);
            setInfo(null);
            setError('');
            ensureKeyPair(userId).catch((err) => setError(intl.formatMessage({id: 'secrets.modal.keyError', defaultMessage: 'Could not set up your key: {message}'}, {message: err.message})));
            getRecipients(detail.channelId).then(setInfo).catch((err) => setError(err.message));
        };
        window.addEventListener(openEvent, onOpen);
        return () => window.removeEventListener(openEvent, onOpen);
    }, [userId, intl]);

    const close = useCallback(() => {
        cancelled.current = true;
        setTarget(null);
        setText('');
        setFile(null);
    }, []);

    const send = useCallback(async () => {
        if (!target || !info) {
            return;
        }
        cancelled.current = false;
        setBusy(true);
        setError('');
        let uploadId = '';
        try {
            let plaintext = text;
            let version: EnvelopeVersion = 1;
            let attachment: FileAttachment | undefined;
            if (file) {
                const upload = await createUpload(target.channelId, file.size);
                uploadId = upload.upload_id;
                const fk = await generateFileKey();
                setProgress({done: 0, total: chunkCount(file.size, upload.chunk_size)});
                const chunks = await encryptFile(file, uploadId, upload.chunk_size, fk, async (i, ct) => {
                    if (cancelled.current) {
                        throw new Cancelled();
                    }
                    await putChunk(uploadId, i, ct);
                }, (done, total) => setProgress({done, total}));
                const manifest: SecretManifest = {v: 2, text, file: describeFile(file, uploadId, upload.chunk_size, fk)};
                plaintext = JSON.stringify(manifest);
                version = 2;
                attachment = {upload_id: uploadId, chunks, bytes: file.size};
            }
            const envelopes: Record<string, Envelope> = {};
            for (const r of info.recipients) {
                // eslint-disable-next-line no-await-in-loop
                envelopes[r.user_id] = await encryptFor(plaintext, {userId: r.user_id, publicKey: r.public_key, kid: r.kid}, target.channelId, userId, version);
            }
            if (cancelled.current) {
                throw new Cancelled();
            }
            await createSecret(target.channelId, target.rootId, envelopes, attachment);
            uploadId = '';
            close();
        } catch (err) {
            if (!(err instanceof Cancelled)) {
                setError((err as Error).message);
            }
        } finally {
            if (uploadId) {
                deleteUpload(uploadId).catch(() => undefined);
            }
            setBusy(false);
            setProgress(null);
        }
    }, [target, info, text, file, userId, close]);

    if (!target) {
        return null;
    }

    const missing = info?.missing ?? [];
    const maxFileBytes = info?.max_file_bytes ?? 0;
    let fileError = '';
    if (file && file.size === 0) {
        fileError = intl.formatMessage({id: 'secrets.modal.fileEmpty', defaultMessage: 'This file is empty.'});
    } else if (file && file.size > maxFileBytes) {
        fileError = intl.formatMessage({id: 'secrets.modal.fileTooLarge', defaultMessage: 'This file is larger than {max}.'}, {max: formatBytes(maxFileBytes)});
    }
    const hasContent = text.trim().length > 0 || file !== null;
    const canSend = Boolean(info) && missing.length === 0 && hasContent && !fileError && !busy;
    const days = info ? Math.round((info.expiry_minutes / 1440) * 10) / 10 : null;
    let sendLabel = (
        <FormattedMessage
            id='secrets.modal.send'
            defaultMessage='Send secret'
        />
    );
    if (busy && file) {
        sendLabel = (
            <FormattedMessage
                id='secrets.modal.uploading'
                defaultMessage='Uploading...'
            />
        );
    } else if (busy) {
        sendLabel = (
            <FormattedMessage
                id='secrets.modal.encrypting'
                defaultMessage='Encrypting...'
            />
        );
    }

    return (
        <div
            className='Secrets-SecretModal'
            data-testid='secret-modal'
        >
            <div
                className='Secrets-SecretModal__dialog'
                role='dialog'
                aria-labelledby='secrets-modal-title'
            >
                <h2
                    id='secrets-modal-title'
                    className='Secrets-SecretModal__title'
                >
                    <FormattedMessage
                        id='secrets.modal.title'
                        defaultMessage='Send a secret'
                    />
                </h2>
                <p className='Secrets-SecretModal__intro'>
                    <FormattedMessage
                        id='secrets.modal.intro'
                        defaultMessage='Encrypted in this browser for each recipient. The server only stores ciphertext. Each recipient can reveal it once; then it is deleted. '
                    />
                    {days !== null && (
                        <FormattedMessage
                            id='secrets.modal.expiry'
                            defaultMessage='Unread copies are deleted after {days} day(s). '
                            values={{days}}
                        />
                    )}
                    <FormattedMessage
                        id='secrets.modal.lostKey'
                        defaultMessage='If a recipient lost their browser key they cannot read it, so you would need to resend.'
                    />
                </p>
                {info && info.recipients.length > 0 && (
                    <p>
                        <FormattedMessage
                            id='secrets.modal.to'
                            defaultMessage='To: {names}'
                            values={{names: info.recipients.map((r) => '@' + r.username).join(', ')}}
                        />
                    </p>
                )}
                {missing.length > 0 && (
                    <p
                        className='Secrets-SecretModal__error'
                        data-testid='secret-missing-keys'
                    >
                        <FormattedMessage
                            id='secrets.modal.missingKeys'
                            defaultMessage='Cannot send: {names} {count, plural, one {has} other {have}} not set up secret messages yet. They need to open Mattermost on desktop or web once with this plugin enabled.'
                            values={{names: missing.map((u) => '@' + u).join(', '), count: missing.length}}
                        />
                    </p>
                )}
                <textarea
                    data-testid='secret-text'
                    className='form-control Secrets-SecretModal__text'
                    rows={5}
                    maxLength={maxChars}
                    value={text}
                    autoFocus={true}
                    onChange={(e) => setText(e.target.value)}
                    placeholder={intl.formatMessage({id: 'secrets.modal.placeholder', defaultMessage: 'Type the secret'})}
                    aria-label={intl.formatMessage({id: 'secrets.modal.textLabel', defaultMessage: 'Secret text'})}
                    disabled={busy}
                />
                {info?.file_secrets_enabled && (
                    <div className='Secrets-SecretModal__file'>
                        <label
                            htmlFor='secrets-modal-file'
                            className='Secrets-SecretModal__fileLabel'
                        >
                            <FormattedMessage
                                id='secrets.modal.fileLabel'
                                defaultMessage='Attach a file (optional)'
                            />
                        </label>
                        <input
                            id='secrets-modal-file'
                            ref={fileInput}
                            type='file'
                            data-testid='secret-file'
                            aria-describedby='secrets-modal-file-help'
                            disabled={busy}
                            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                        />
                        {file && !busy && (
                            <button
                                className='btn btn-tertiary btn-xs'
                                onClick={() => {
                                    setFile(null);
                                    if (fileInput.current) {
                                        fileInput.current.value = '';
                                    }
                                }}
                            >
                                <FormattedMessage
                                    id='secrets.modal.removeFile'
                                    defaultMessage='Remove file'
                                />
                            </button>
                        )}
                        <p
                            id='secrets-modal-file-help'
                            className={`Secrets-SecretModal__fileNote ${fileError ? 'Secrets-SecretModal__error' : 'Secrets-SecretModal__help'}`}
                        >
                            {fileError || (
                                <FormattedMessage
                                    id='secrets.modal.fileHelp'
                                    defaultMessage='Files up to {max}. Recipients see only the size until they open it.'
                                    values={{max: formatBytes(maxFileBytes)}}
                                />
                            )}
                        </p>
                    </div>
                )}
                <p
                    className='Secrets-SecretModal__progress'
                    role='status'
                    aria-live='polite'
                >
                    {progress && (
                        <FormattedMessage
                            id='secrets.modal.progress'
                            defaultMessage='Encrypting and uploading the file: {percent}%'
                            values={{percent: Math.round((progress.done / progress.total) * 100)}}
                        />
                    )}
                </p>
                {error && (
                    <p
                        className='Secrets-SecretModal__error'
                        role='alert'
                    >{error}</p>
                )}
                <div className='Secrets-SecretModal__actions'>
                    <button
                        className='btn btn-tertiary'
                        onClick={close}
                    >
                        <FormattedMessage
                            id='secrets.modal.cancel'
                            defaultMessage='Cancel'
                        />
                    </button>
                    <button
                        data-testid='secret-send'
                        className='btn btn-primary'
                        disabled={!canSend}
                        onClick={send}
                    >{sendLabel}</button>
                </div>
            </div>
        </div>
    );
}
