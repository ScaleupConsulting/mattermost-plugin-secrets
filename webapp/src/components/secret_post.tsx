import React, {useCallback, useEffect, useState} from 'react';
import {FormattedMessage, useIntl} from 'react-intl';
import {useSelector} from 'react-redux';

import type {Post} from '@mattermost/types/posts';
import type {GlobalState} from '@mattermost/types/store';

import {getCurrentUserId} from 'mattermost-redux/selectors/entities/users';

import {ackSecret, ApiError, getEnvelope, getFileChunk, getStatus} from '../client';
import type {SecretStatus} from '../client';
import {decryptEnvelope} from '../crypto';
import {decryptFile, safeFileName} from '../file_crypto';
import type {SecretManifest} from '../file_crypto';
import {formatBytes} from '../format';
import {ensureKeyPair} from '../keys';

import './secret_post.css';

type OpenedFile = {name: string; size: number; blob: Blob};

type View =
    | {kind: 'idle'}
    | {kind: 'busy'; done?: number; total?: number}
    | {kind: 'revealed'; text: string; file?: OpenedFile}
    | {kind: 'downloaded'}
    | {kind: 'gone'}
    | {kind: 'error'; message: string};

/**
 * Saves a Blob under a file name without putting its content in the DOM.
 * @param blob - the content
 * @param name - the file name
 */
function saveBlob(blob: Blob, name: string) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    link.click();
    URL.revokeObjectURL(url);
}

/**
 * Saves the secret as a text file.
 * @param text - the decrypted secret
 * @param postId - the secret post's ID, used in the file name
 */
function downloadText(text: string, postId: string) {
    saveBlob(new Blob([text], {type: 'text/plain;charset=utf-8'}), `secret-${postId}.txt`);
}

/**
 * Saves a decrypted file as opaque bytes so the browser never renders or sniffs it.
 * @param file - the decrypted file
 */
function saveFile(file: OpenedFile) {
    saveBlob(new Blob([file.blob], {type: 'application/octet-stream'}), file.name);
}

/**
 * Parses a v2 envelope's plaintext.
 * @param plaintext - the decrypted envelope
 * @returns the manifest
 */
function parseManifest(plaintext: string): SecretManifest {
    const m = JSON.parse(plaintext) as SecretManifest;
    if (m?.v !== 2 || typeof m.text !== 'string' || typeof m.file !== 'object' || m.file === null) {
        throw new Error('invalid manifest');
    }
    return m;
}

/**
 * Renders a custom_secret post: Reveal and Download buttons for recipients, read status for the sender.
 * Version 2 posts carry an encrypted file that is fetched, decrypted and verified before the secret is acked.
 * @param props - the component props
 * @param props.post - the secret post
 * @returns the rendered post body
 */
export default function SecretPost({post}: {post: Post}) {
    const intl = useIntl();
    const userId = useSelector((state: GlobalState) => getCurrentUserId(state));
    const meta = post.props as Record<string, unknown>;
    const recipients = (meta.secret_recipients as string[] | undefined) ?? [];
    const isFile = Number(meta.secret_v) === 2;
    const fileBytes = Number(meta.secret_file_bytes) || 0;
    const isBurned = Boolean(meta.secret_burned);
    const isSender = post.user_id === userId;
    const isRecipient = recipients.includes(userId);
    const [view, setView] = useState<View>({kind: 'idle'});
    const [status, setStatus] = useState<SecretStatus | null>(null);

    useEffect(() => {
        if (isSender && !isBurned) {
            getStatus(post.id).then(setStatus).catch(() => setStatus(null));
        }
    }, [isSender, isBurned, post.id, post.update_at]);

    const open = useCallback(async (isDownload: boolean) => {
        setView({kind: 'busy'});
        const lostKey = intl.formatMessage({
            id: 'secrets.post.lostKey',
            defaultMessage: 'This browser cannot decrypt the secret: its key was lost or replaced. Ask the sender to send it again.',
        });
        let env;
        try {
            env = await getEnvelope(post.id);
        } catch (e) {
            setView(e instanceof ApiError && e.status === 410 ? {kind: 'gone'} : {kind: 'error', message: (e as Error).message});
            return;
        }
        let text;
        try {
            const pair = await ensureKeyPair(userId);
            text = await decryptEnvelope(env, pair.privateKey, post.channel_id, post.user_id, userId, isFile ? 2 : 1);
        } catch {
            setView({kind: 'error', message: lostKey});
            return;
        }
        let file: OpenedFile | undefined;
        if (isFile) {
            try {
                const m = parseManifest(text);
                text = m.text;
                const blob = await decryptFile(m.file, (i) => getFileChunk(post.id, i), (done, total) => setView({kind: 'busy', done, total}));
                file = {name: safeFileName(m.file.name), size: m.file.size, blob};
            } catch (e) {
                // Nothing is acked, so the recipient can try again.
                if (e instanceof ApiError && e.status === 410) {
                    setView({kind: 'gone'});
                    return;
                }
                const message = e instanceof ApiError ? e.message : intl.formatMessage({
                    id: 'secrets.post.fileCorrupt',
                    defaultMessage: 'The file could not be decrypted: it is incomplete or was tampered with. Try again, or ask the sender to send it again.',
                });
                setView({kind: 'error', message});
                return;
            }
        }
        if (isDownload && !file) {
            downloadText(text, post.id);
            setView({kind: 'downloaded'});
        } else {
            setView({kind: 'revealed', text, file});
        }
        ackSecret(post.id).catch((e) => setView({
            kind: 'error',
            message: intl.formatMessage({id: 'secrets.post.ackFailed', defaultMessage: 'Opened, but the server could not delete its copy: {message}'}, {message: e.message}),
        }));
    }, [post.id, post.channel_id, post.user_id, userId, isFile, intl]);

    const sizeNote = isFile ? (
        <span
            className='Secrets-SecretPost__note'
            data-testid='secret-file-size'
        >
            <FormattedMessage
                id='secrets.post.fileSize'
                defaultMessage='Encrypted file, {size}'
                values={{size: formatBytes(fileBytes)}}
            />
        </span>
    ) : null;

    let body: React.ReactNode;
    if (view.kind === 'revealed') {
        const {text, file} = view;
        body = (
            <>
                {text !== '' && (
                    <button
                        data-testid='secret-download'
                        className='btn btn-tertiary btn-xs'
                        onClick={() => downloadText(text, post.id)}
                    >
                        <FormattedMessage
                            id='secrets.post.download'
                            defaultMessage='Download'
                        />
                    </button>
                )}
                <span className='Secrets-SecretPost__note'>
                    <FormattedMessage
                        id='secrets.post.revealedNote'
                        defaultMessage='Deleted from the server. Copy, download or save it now: it will not show again after you leave or reload.'
                    />
                </span>
                {text !== '' && (
                    <div
                        className='Secrets-SecretPost__full Secrets-SecretPost__text'
                        data-testid='secret-revealed'
                    >{text}</div>
                )}
                {file && (
                    <div className='Secrets-SecretPost__full Secrets-SecretPost__file'>
                        <span
                            className='Secrets-SecretPost__fileName'
                            data-testid='secret-file-name'
                        >{file.name}</span>
                        <span className='Secrets-SecretPost__note'>{formatBytes(file.size)}</span>
                        <button
                            data-testid='secret-save-file'
                            className='btn btn-primary btn-xs'
                            onClick={() => saveFile(file)}
                        >
                            <FormattedMessage
                                id='secrets.post.saveFile'
                                defaultMessage='Save file'
                            />
                        </button>
                    </div>
                )}
            </>
        );
    } else if (view.kind === 'downloaded') {
        body = (
            <span data-testid='secret-downloaded'>
                <FormattedMessage
                    id='secrets.post.downloaded'
                    defaultMessage='Downloaded and deleted from the server.'
                />
            </span>
        );
    } else if (isBurned || view.kind === 'gone') {
        body = (
            <span data-testid='secret-burned'>
                <FormattedMessage
                    id='secrets.post.burned'
                    defaultMessage='Burned: this secret has been read or has expired.'
                />
            </span>
        );
    } else if (isRecipient) {
        const isBusy = view.kind === 'busy';
        let openLabel = isFile ? (
            <FormattedMessage
                id='secrets.post.open'
                defaultMessage='Open'
            />
        ) : (
            <FormattedMessage
                id='secrets.post.reveal'
                defaultMessage='Reveal'
            />
        );
        if (isBusy) {
            openLabel = (
                <FormattedMessage
                    id='secrets.post.decrypting'
                    defaultMessage='Decrypting...'
                />
            );
        }
        body = (
            <>
                {sizeNote}
                <span className='Secrets-SecretPost__actions'>
                    <button
                        data-testid='secret-reveal'
                        className='btn btn-primary btn-xs'
                        disabled={isBusy}
                        onClick={() => open(false)}
                    >{openLabel}</button>
                    {!isFile && (
                        <button
                            data-testid='secret-download'
                            className='btn btn-tertiary btn-xs'
                            disabled={isBusy}
                            onClick={() => open(true)}
                        >
                            <FormattedMessage
                                id='secrets.post.download'
                                defaultMessage='Download'
                            />
                        </button>
                    )}
                </span>
                <span
                    className='Secrets-SecretPost__note'
                    role='status'
                    aria-live='polite'
                >
                    {view.kind === 'busy' && view.total ? (
                        <FormattedMessage
                            id='secrets.post.progress'
                            defaultMessage='Downloading and decrypting: {percent}%'
                            values={{percent: Math.round(((view.done ?? 0) / view.total) * 100)}}
                        />
                    ) : (
                        <FormattedMessage
                            id='secrets.post.once'
                            defaultMessage='You can open it once.'
                        />
                    )}
                </span>
                {view.kind === 'error' && (
                    <div
                        className='Secrets-SecretPost__full Secrets-SecretPost__error'
                        role='alert'
                    >{view.message}</div>
                )}
            </>
        );
    } else if (isSender) {
        const left = status?.remaining?.length ?? null;
        body = (
            <span data-testid='secret-sender-status'>
                {sizeNote}
                {' '}
                {left === null ? (
                    <FormattedMessage
                        id='secrets.post.sent'
                        defaultMessage='Secret sent.'
                    />
                ) : (
                    <FormattedMessage
                        id='secrets.post.sentUnread'
                        defaultMessage='Secret sent. Unread by {left} of {total} recipient(s).'
                        values={{left, total: recipients.length}}
                    />
                )}
                {status && (
                    <>
                        {' '}
                        <FormattedMessage
                            id='secrets.post.expires'
                            defaultMessage='Unread copies expire {when}.'
                            values={{when: new Date(status.expires_at).toLocaleString()}}
                        />
                    </>
                )}
            </span>
        );
    } else {
        body = (
            <span>
                <FormattedMessage
                    id='secrets.post.forOthers'
                    defaultMessage='Secret message for other members of this conversation.'
                />
            </span>
        );
    }

    return (
        <div
            className='Secrets-SecretPost'
            data-testid='secret-post'
        >
            <span className='Secrets-SecretPost__title'>
                {'\u{1F512} '}
                <FormattedMessage
                    id='secrets.post.title'
                    defaultMessage='Secret message'
                />
            </span>
            {body}
        </div>
    );
}
