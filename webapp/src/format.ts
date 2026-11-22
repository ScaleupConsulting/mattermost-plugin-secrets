/**
 * Formats a byte count the way the settings count it (1 MB = 1024 * 1024 bytes).
 * @param bytes - the size
 * @returns e.g. "820 KB" or "12.3 MB"
 */
export function formatBytes(bytes: number): string {
    if (bytes < 1024) {
        return `${bytes} B`;
    }
    if (bytes < 1024 * 1024) {
        return `${Math.round(bytes / 1024)} KB`;
    }
    const mb = bytes / (1024 * 1024);
    return `${mb < 100 ? mb.toFixed(1) : Math.round(mb)} MB`;
}
