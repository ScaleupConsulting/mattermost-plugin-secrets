import {getMyKey, registerKey} from './client';
import {exportPublicKey, generateKeyPair} from './crypto';
import {loadKeyPair, saveKeyPair} from './keystore';

const ensuring = new Map<string, Promise<CryptoKeyPair>>();

/**
 * Makes sure this browser holds a key pair for the user and that the server has its public half.
 * It exists so recipients can be encrypted to before they ever open the composer.
 * The last browser to register wins; secrets sent to an older key become unreadable.
 * @param userId - the current Mattermost user
 * @returns this browser's key pair
 */
export function ensureKeyPair(userId: string): Promise<CryptoKeyPair> {
    let pending = ensuring.get(userId);
    if (!pending) {
        pending = (async () => {
            let pair = await loadKeyPair(userId);
            if (!pair) {
                pair = await generateKeyPair();
                await saveKeyPair(userId, pair);
            }
            const pub = await exportPublicKey(pair.publicKey);
            const server = await getMyKey();
            if (server?.public_key !== pub) {
                await registerKey(pub);
            }
            return pair;
        })();
        ensuring.set(userId, pending);
        pending.catch(() => ensuring.delete(userId));
    }
    return pending;
}
