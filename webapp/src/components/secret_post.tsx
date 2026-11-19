import React, {useCallback, useEffect, useState} from 'react';
import {useSelector} from 'react-redux';

import type {Post} from '@mattermost/types/posts';
import type {GlobalState} from '@mattermost/types/store';

import {getCurrentUserId} from 'mattermost-redux/selectors/entities/users';

import {ackSecret, ApiError, getEnvelope, getStatus} from '../client';
import type {SecretStatus} from '../client';
import {decryptEnvelope} from '../crypto';
import {ensureKeyPair} from '../keys';

import './secret_post.css';

type View = {kind: 'idle'} | {kind: 'busy'} | {kind: 'revealed'; text: string} | {kind: 'downloaded'} | {kind: 'gone'} | {kind: 'error'; message: string};

/**
 * Saves the secret as a text file without putting it in the DOM.
 * @param text - the decrypted secret
 * @param postId - the secret post's ID, used in the file name
 */
function downloadText(text: string, postId: string) {
    const url = URL.createObjectURL(new Blob([text], {type: 'text/plain;charset=utf-8'}));
    const link = document.createElement('a');
    link.href = url;
    link.download = `secret-${postId}.txt`;
    link.click();
    URL.revokeObjectURL(url);
}

/**
 * Renders a custom_secret post: Reveal and Download buttons for recipients, read status for the sender.
 * @param props - the component props
 * @param props.post - the secret post
 * @returns the rendered post body
 */
export default function SecretPost({post}: {post: Post}) {
    const userId = useSelector((state: GlobalState) => getCurrentUserId(state));
    const meta = post.props as Record<string, unknown>;
    const recipients = (meta.secret_recipients as string[] | undefined) ?? [];
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
            text = await decryptEnvelope(env, pair.privateKey, post.channel_id, post.user_id, userId);
        } catch {
            setView({kind: 'error', message: 'This browser cannot decrypt the secret: its key was lost or replaced. Ask the sender to send it again.'});
            return;
        }
        if (isDownload) {
            downloadText(text, post.id);
            setView({kind: 'downloaded'});
        } else {
            setView({kind: 'revealed', text});
        }
        ackSecret(post.id).catch((e) => setView({kind: 'error', message: `Opened, but the server could not delete its copy: ${e.message}`}));
    }, [post.id, post.channel_id, post.user_id, userId]);

    let body: React.ReactNode;
    if (view.kind === 'revealed') {
        const text = view.text;
        body = (
            <>
                <button
                    data-testid='secret-download'
                    className='btn btn-tertiary btn-xs'
                    onClick={() => downloadText(text, post.id)}
                >{'Download'}</button>
                <span className='Secrets-SecretPost__note'>{'Deleted from the server. Copy or download it now: it will not show again after you leave or reload.'}</span>
                <div
                    className='Secrets-SecretPost__full Secrets-SecretPost__text'
                    data-testid='secret-revealed'
                >{text}</div>
            </>
        );
    } else if (view.kind === 'downloaded') {
        body = <span data-testid='secret-downloaded'>{'Downloaded and deleted from the server.'}</span>;
    } else if (isBurned || view.kind === 'gone') {
        body = <span data-testid='secret-burned'>{'Burned: this secret has been read or has expired.'}</span>;
    } else if (isRecipient) {
        const isBusy = view.kind === 'busy';
        body = (
            <>
                <span className='Secrets-SecretPost__actions'>
                    <button
                        data-testid='secret-reveal'
                        className='btn btn-primary btn-xs'
                        disabled={isBusy}
                        onClick={() => open(false)}
                    >{isBusy ? 'Decrypting...' : 'Reveal'}</button>
                    <button
                        data-testid='secret-download'
                        className='btn btn-tertiary btn-xs'
                        disabled={isBusy}
                        onClick={() => open(true)}
                    >{'Download'}</button>
                </span>
                <span className='Secrets-SecretPost__note'>{'You can open it once.'}</span>
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
                {left === null ? 'Secret sent.' : `Secret sent. Unread by ${left} of ${recipients.length} recipient(s).`}
                {status ? ` Unread copies expire ${new Date(status.expires_at).toLocaleString()}.` : ''}
            </span>
        );
    } else {
        body = <span>{'Secret message for other members of this conversation.'}</span>;
    }

    return (
        <div
            className='Secrets-SecretPost'
            data-testid='secret-post'
        >
            <span className='Secrets-SecretPost__title'>{'\u{1F512} Secret message'}</span>
            {body}
        </div>
    );
}
