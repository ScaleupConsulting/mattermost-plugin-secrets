import React, {useCallback, useEffect, useState} from 'react';
import {useSelector} from 'react-redux';

import type {GlobalState} from '@mattermost/types/store';

import {getCurrentUserId} from 'mattermost-redux/selectors/entities/users';

import {createSecret, getRecipients} from '../client';
import type {Recipients} from '../client';
import {encryptFor} from '../crypto';
import type {Envelope} from '../crypto';
import {openEvent} from '../events';
import type {OpenDetail} from '../events';
import {ensureKeyPair} from '../keys';

const maxChars = 4000;

const overlay: React.CSSProperties = {position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 2000, display: 'flex', alignItems: 'center', justifyContent: 'center'};
const dialog: React.CSSProperties = {background: 'var(--center-channel-bg)', color: 'var(--center-channel-color)', borderRadius: 8, padding: 24, width: 520, maxWidth: '92vw', boxShadow: '0 8px 24px rgba(0,0,0,0.3)'};
const errorStyle: React.CSSProperties = {color: 'var(--error-text, #d24b4e)', margin: '8px 0'};

/**
 * Root-mounted modal that encrypts a secret in the browser for every recipient and uploads only ciphertext.
 * @returns the modal, or nothing while closed
 */
export default function SecretModal() {
    const userId = useSelector((state: GlobalState) => getCurrentUserId(state));
    const [target, setTarget] = useState<OpenDetail | null>(null);
    const [text, setText] = useState('');
    const [info, setInfo] = useState<Recipients | null>(null);
    const [error, setError] = useState('');
    const [busy, setBusy] = useState(false);

    useEffect(() => {
        /**
         * Opens the modal for the channel named in the event and loads its recipients' keys.
         * @param e - the open event
         */
        const onOpen = (e: Event) => {
            const detail = (e as CustomEvent<OpenDetail>).detail;
            setTarget(detail);
            setText(detail.text);
            setInfo(null);
            setError('');
            ensureKeyPair(userId).catch((err) => setError(`Could not set up your key: ${err.message}`));
            getRecipients(detail.channelId).then(setInfo).catch((err) => setError(err.message));
        };
        window.addEventListener(openEvent, onOpen);
        return () => window.removeEventListener(openEvent, onOpen);
    }, [userId]);

    const close = useCallback(() => {
        setTarget(null);
        setText('');
    }, []);

    const send = useCallback(async () => {
        if (!target || !info) {
            return;
        }
        setBusy(true);
        setError('');
        try {
            const envelopes: Record<string, Envelope> = {};
            for (const r of info.recipients) {
                // eslint-disable-next-line no-await-in-loop
                envelopes[r.user_id] = await encryptFor(text, {userId: r.user_id, publicKey: r.public_key, kid: r.kid}, target.channelId, userId);
            }
            await createSecret(target.channelId, target.rootId, envelopes);
            close();
        } catch (err) {
            setError((err as Error).message);
        } finally {
            setBusy(false);
        }
    }, [target, info, text, userId, close]);

    if (!target) {
        return null;
    }

    const missing = info?.missing ?? [];
    const canSend = Boolean(info) && missing.length === 0 && text.trim().length > 0 && !busy;
    const days = info ? Math.round((info.expiry_minutes / 1440) * 10) / 10 : null;

    return (
        <div
            style={overlay}
            data-testid='secret-modal'
        >
            <div
                style={dialog}
                role='dialog'
                aria-label='Send a secret'
            >
                <h2 style={{marginTop: 0}}>{'Send a secret'}</h2>
                <p style={{opacity: 0.8}}>
                    {'Encrypted in this browser for each recipient. The server only stores ciphertext. Each recipient can reveal it once; then it is deleted. '}
                    {days === null ? '' : `Unread copies are deleted after ${days} day(s). `}
                    {'If a recipient lost their browser key they cannot read it, so you would need to resend.'}
                </p>
                {info && info.recipients.length > 0 && (
                    <p>{'To: '}{info.recipients.map((r) => '@' + r.username).join(', ')}</p>
                )}
                {missing.length > 0 && (
                    <p
                        style={errorStyle}
                        data-testid='secret-missing-keys'
                    >
                        {`Cannot send: ${missing.map((u) => '@' + u).join(', ')} ${missing.length === 1 ? 'has' : 'have'} not set up secret messages yet. They need to open Mattermost on desktop or web once with this plugin enabled.`}
                    </p>
                )}
                <textarea
                    data-testid='secret-text'
                    className='form-control'
                    rows={5}
                    maxLength={maxChars}
                    value={text}
                    autoFocus={true}
                    onChange={(e) => setText(e.target.value)}
                    placeholder='Type the secret'
                    style={{width: '100%', fontFamily: 'monospace'}}
                />
                {error && <p style={errorStyle}>{error}</p>}
                <div style={{display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16}}>
                    <button
                        className='btn btn-tertiary'
                        onClick={close}
                    >{'Cancel'}</button>
                    <button
                        data-testid='secret-send'
                        className='btn btn-primary'
                        disabled={!canSend}
                        onClick={send}
                    >{busy ? 'Encrypting...' : 'Send secret'}</button>
                </div>
            </div>
        </div>
    );
}
