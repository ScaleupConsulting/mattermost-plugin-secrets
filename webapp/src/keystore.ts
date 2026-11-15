// Adapted from quarkslab/mattermost-plugin-e2ee webapp/src/keystore.ts (Apache-2.0), which was
// itself adapted from infotechinc/key-storage-in-browser (MIT). See NOTICE.

const dbName = 'mm-secrets';
const objectStoreName = 'keys';

/**
 * Opens the IndexedDB database that holds this browser's secret-message key pairs.
 * It exists because a non-extractable CryptoKey can only persist via structured clone into IndexedDB.
 * @returns the open database
 */
function openDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
        if (!window.indexedDB) {
            reject(new Error('IndexedDB is not supported by this browser.'));
            return;
        }
        const req = indexedDB.open(dbName, 1);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
        req.onblocked = () => reject(new Error('Key database is blocked by another tab.'));
        req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains(objectStoreName)) {
                db.createObjectStore(objectStoreName, {keyPath: 'name'});
            }
        };
    });
}

/**
 * Loads the key pair saved under name, or null when this browser has none.
 * @param name - the record name, the Mattermost user ID
 * @returns the stored key pair or null
 */
export async function loadKeyPair(name: string): Promise<CryptoKeyPair | null> {
    const db = await openDB();
    try {
        return await new Promise((resolve, reject) => {
            const req = db.transaction([objectStoreName], 'readonly').objectStore(objectStoreName).get(name);
            req.onsuccess = () => resolve(req.result ? req.result.key as CryptoKeyPair : null);
            req.onerror = () => reject(req.error);
        });
    } finally {
        db.close();
    }
}

/**
 * Saves a key pair under name, replacing any earlier pair.
 * @param name - the record name, the Mattermost user ID
 * @param key - the key pair; its private key stays non-extractable
 */
export async function saveKeyPair(name: string, key: CryptoKeyPair): Promise<void> {
    if (navigator.storage?.persist) {
        await navigator.storage.persist();
    }
    const db = await openDB();
    try {
        await new Promise<void>((resolve, reject) => {
            const tx = db.transaction([objectStoreName], 'readwrite');
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
            tx.onabort = () => reject(tx.error);
            tx.objectStore(objectStoreName).put({name, key});
        });
    } finally {
        db.close();
    }
}
