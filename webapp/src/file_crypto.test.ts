import {decryptEnvelope, encryptFor, exportPublicKey, generateKeyPair} from './crypto';
import {chunkCount, decryptFile, describeFile, encryptFile, generateFileKey, safeFileName} from './file_crypto';
import type {FileManifest} from './file_crypto';

const uploadId = 'u'.repeat(26);
const chunkSize = 1024;

/**
 * Encrypts a file of the given size and returns its chunks and manifest.
 * @param size - plaintext bytes
 * @returns the plaintext, chunks and manifest
 */
async function encrypted(size: number) {
    const plain = crypto.getRandomValues(new Uint8Array(size));
    const file = new File([plain], 'report.pdf', {type: 'application/pdf'});
    const fk = await generateFileKey();
    const chunks: Uint8Array[] = [];
    const n = await encryptFile(file, uploadId, chunkSize, fk, async (i, ct) => {
        chunks[i] = ct;
    });
    return {plain, chunks, n, manifest: describeFile(file, uploadId, chunkSize, fk)};
}

/**
 * Serves chunks to decryptFile as an ArrayBuffer per index.
 * @param chunks - the stored chunks
 * @returns a fetchChunk function
 */
function server(chunks: Uint8Array[]) {
    return async (i: number) => {
        if (!chunks[i]) {
            throw new Error('gone');
        }
        return chunks[i].slice().buffer;
    };
}

/**
 * Reads a Blob into bytes.
 * @param b - the blob
 * @returns its bytes
 */
async function bytes(b: Blob) {
    return new Uint8Array(await b.arrayBuffer());
}

describe('file_crypto', () => {
    test.each([1, chunkSize - 1, chunkSize, chunkSize + 1, (3 * chunkSize) + 17])('round trips %i bytes', async (size) => {
        const {plain, chunks, n, manifest} = await encrypted(size);
        expect(n).toBe(chunkCount(size, chunkSize));
        expect(chunks).toHaveLength(n);
        chunks.forEach((c, i) => expect(c.length).toBe((i < n - 1 ? chunkSize : size - ((n - 1) * chunkSize)) + 16));
        const progress: number[] = [];
        const out = await decryptFile(manifest, server(chunks), (done) => progress.push(done));
        expect(await bytes(out)).toEqual(plain);
        expect(out.type).toBe('application/octet-stream');
        expect(progress).toEqual(Array.from({length: n}, (_, i) => i + 1));
    });

    test('rejects a tampered chunk', async () => {
        const {chunks, manifest} = await encrypted(2 * chunkSize);
        chunks[1][0] ^= 1;
        await expect(decryptFile(manifest, server(chunks))).rejects.toThrow();
    });

    test('rejects swapped chunks', async () => {
        const {chunks, manifest} = await encrypted(3 * chunkSize);
        [chunks[0], chunks[1]] = [chunks[1], chunks[0]];
        await expect(decryptFile(manifest, server(chunks))).rejects.toThrow();
    });

    test('rejects truncation, even when the manifest is edited to match', async () => {
        const {chunks, manifest} = await encrypted((2 * chunkSize) + 5);
        const shorter: FileManifest = {...manifest, size: 2 * chunkSize, chunks: 2};
        await expect(decryptFile(shorter, server(chunks.slice(0, 2)))).rejects.toThrow();
    });

    test('rejects a wrong upload ID', async () => {
        const {chunks, manifest} = await encrypted(chunkSize + 1);
        await expect(decryptFile({...manifest, upload_id: 'x'.repeat(26)}, server(chunks))).rejects.toThrow();
    });

    test('rejects a chunk from another file', async () => {
        const a = await encrypted(2 * chunkSize);
        const b = await encrypted(2 * chunkSize);
        await expect(decryptFile(a.manifest, server([a.chunks[0], b.chunks[1]]))).rejects.toThrow();
    });

    test('rejects a manifest whose chunk count disagrees with its size', async () => {
        const {chunks, manifest} = await encrypted(chunkSize + 1);
        await expect(decryptFile({...manifest, chunks: 3}, server(chunks))).rejects.toThrow('invalid');
    });

    test('v1 and v2 envelopes cannot be read as each other', async () => {
        const pair = await generateKeyPair();
        const recipient = {userId: 'r', publicKey: await exportPublicKey(pair.publicKey), kid: 'k'};
        const v2 = await encryptFor('{"v":2}', recipient, 'c', 's', 2);
        await expect(decryptEnvelope(v2, pair.privateKey, 'c', 's', 'r', 1)).rejects.toThrow();
        expect(await decryptEnvelope(v2, pair.privateKey, 'c', 's', 'r', 2)).toBe('{"v":2}');
        const v1 = await encryptFor('text', recipient, 'c', 's');
        await expect(decryptEnvelope(v1, pair.privateKey, 'c', 's', 'r', 2)).rejects.toThrow();
        expect(await decryptEnvelope(v1, pair.privateKey, 'c', 's', 'r')).toBe('text');
    });

    test.each([
        ['report.pdf', 'report.pdf'],
        ['../../etc/passwd', 'passwd'],
        ['C:\\Users\\x\\evil.exe', 'evil.exe'],
        ['.bashrc', 'bashrc'],
        ['a\u0000b<c>.txt', 'a_b_c_.txt'],
        ['', 'secret-file'],
        ['..', 'secret-file'],
    ])('safeFileName(%j) is %j', (name, want) => {
        expect(safeFileName(name)).toBe(want);
    });
});
