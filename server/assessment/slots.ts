import { TargetError, normalizeTarget } from '../net';

const hosts = new Set<string>();
let active = 0;
/** Shared by recon and crawl: reject work instead of accumulating an unbounded queue. */
export async function withScanSlot<T>(input: string, work: () => Promise<T>): Promise<T> {
    const host = normalizeTarget(input).hostname;
    if (active >= 2 || hosts.has(host)) throw new TargetError('Scanner busy. At most two scans and one scan per hostname can run at once; retry shortly.', 429);
    active++; hosts.add(host);
    try { return await work(); } finally { active--; hosts.delete(host); }
}
