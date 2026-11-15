import React, {useCallback, useEffect, useState} from 'react';
import {useSelector} from 'react-redux';

import type {Post} from '@mattermost/types/posts';
import type {GlobalState} from '@mattermost/types/store';

import {getCurrentUserId} from 'mattermost-redux/selectors/entities/users';

import {ackSecret, ApiError, getEnvelope, getStatus} from '../client';
import type {SecretStatus} from '../client';
import {decryptEnvelope} from '../crypto';
import {ensureKeyPair} from '../keys';

type View = {kind: 'idle'} | {kind: 'busy'} | {kind: 'revealed'; text: string} | {kind: 'gone'} | {kind: 'error'; message: string};

const box: React.CSSProperties = {border: '1px solid rgba(var(--center-channel-color-rgb), 0.16)', borderRadius: 4, padding: '8px 12px', marginTop: 4, maxWidth: 560};
const secretText: React.CSSProperties = {whiteSpace: 'pre-wrap', fontFamily: 'monospace', background: 'rgba(var(--center-channel-color-rgb), 0.06)', padding: 8, borderRadius: 4, userSelect: 'all'};

/**
 * Renders a custom_secret post: a Reveal button for recipients, read status for the sender.
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

    const reveal = useCallback(async () => {
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
        setView({kind: 'revealed', text});
        ackSecret(post.id).catch((e) => setView({kind: 'error', message: `Revealed, but the server could not delete its copy: ${e.message}`}));
    }, [post.id, post.channel_id, post.user_id, userId]);

    let body: React.ReactNode;
    if (view.kind === 'revealed') {
        body = (
            <>
                <div
                    style={secretText}
                    data-testid='secret-revealed'
                >{view.text}</div>
                <div style={{opacity: 0.7, fontSize: 12, marginTop: 4}}>{'Deleted from the server. Copy it now: it will not show again after you leave or reload.'}</div>
            </>
        );
    } else if (isBurned || view.kind === 'gone') {
        body = <span data-testid='secret-burned'>{'Burned: this secret has been read or has expired.'}</span>;
    } else if (isRecipient) {
        body = (
            <>
                <button
                    data-testid='secret-reveal'
                    className='btn btn-primary btn-sm'
                    disabled={view.kind === 'busy'}
                    onClick={reveal}
                >{view.kind === 'busy' ? 'Decrypting...' : 'Reveal secret'}</button>
                <span style={{marginLeft: 8, opacity: 0.7, fontSize: 12}}>{'You can reveal it once.'}</span>
                {view.kind === 'error' && <div style={{color: 'var(--error-text, #d24b4e)', marginTop: 4}}>{view.message}</div>}
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
            style={box}
            data-testid='secret-post'
        >
            <div style={{fontWeight: 600, marginBottom: 4}}>{'\u{1F512} Secret message'}</div>
            {body}
        </div>
    );
}
