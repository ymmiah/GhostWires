// GhostWires Mk.IV — attack-surface discovery from PUBLIC sources only:
// robots.txt, sitemap.xml, security.txt, Certificate Transparency (crt.sh), Wayback Machine CDX.
import type { RobotsIntel, SitemapIntel, SecurityTxt, CTIntel, WaybackIntel } from '../types';
import { safeFetch, fetchPublicJson, politeDelay } from './net';

const cache = new Map<string, { at: number; value: any }>();
async function cached<T>(key: string, ttlMs: number, fn: () => Promise<T>): Promise<T> {
    const hit = cache.get(key);
    if (hit && Date.now() - hit.at < ttlMs) return hit.value as T;
    const value = await fn();
    if (!(value as any)?.error) cache.set(key, { at: Date.now(), value }); // never cache failures
    if (cache.size > 500) cache.delete(cache.keys().next().value!);
    return value;
}

export function parseRobots(raw: string, agent = '*'): RobotsIntel {
    const disallow: string[] = [], allow: string[] = [], sitemaps: string[] = [];
    let crawlDelay: number | undefined;
    let applies = false;
    let sawRule = false;
    for (const line of raw.split(/\r?\n/)) {
        const clean = line.replace(/#.*/, '').trim();
        const m = clean.match(/^([A-Za-z-]+)\s*:\s*(.*)$/);
        if (!m) continue;
        const key = m[1].toLowerCase(), val = m[2].trim();
        if (key === 'sitemap') { sitemaps.push(val); continue; }
        if (key === 'user-agent') {
            if (sawRule) { applies = false; sawRule = false; }
            if (val === '*' || val.toLowerCase().includes(agent.toLowerCase())) applies = true;
            continue;
        }
        sawRule = true;
        if (!applies) continue;
        if (key === 'disallow' && val) disallow.push(val);
        if (key === 'allow' && val) allow.push(val);
        if (key === 'crawl-delay' && !isNaN(+val)) crawlDelay = +val;
    }
    return { found: true, disallow: [...new Set(disallow)], allow: [...new Set(allow)], sitemaps: [...new Set(sitemaps)], crawlDelay, raw: raw.slice(0, 5000) };
}

export function robotsAllows(robots: RobotsIntel, path: string): boolean {
    if (!robots.found) return true;
    const match = (rule: string) => {
        const re = new RegExp('^' + rule.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\\\$$/, '$'));
        return re.test(path);
    };
    const longest = (rules: string[]) => rules.filter(match).reduce((m, r) => Math.max(m, r.length), -1);
    return longest(robots.allow) >= longest(robots.disallow);
}

export async function robotsIntel(origin: string): Promise<RobotsIntel> {
    return cached(`robots:${origin}`, 10 * 60_000, async () => {
        try {
            const res = await safeFetch(`${origin}/robots.txt`, { timeoutMs: 8000, maxBytes: 512 * 1024, accept: 'text/plain' });
            if (res.status !== 200 || /<html/i.test(res.text.slice(0, 500))) return { found: false, disallow: [], allow: [], sitemaps: [] };
            return parseRobots(res.text, 'GhostWires');
        } catch { return { found: false, disallow: [], allow: [], sitemaps: [] }; }
    });
}

export async function sitemapIntel(origin: string, robots: RobotsIntel): Promise<SitemapIntel> {
    const candidates = [...robots.sitemaps, `${origin}/sitemap.xml`, `${origin}/sitemap_index.xml`];
    for (const src of [...new Set(candidates)].slice(0, 4)) {
        try {
            const res = await safeFetch(src, { timeoutMs: 10000, maxBytes: 5 * 1024 * 1024, accept: 'application/xml,text/xml' });
            if (res.status !== 200 || !/<(urlset|sitemapindex)/i.test(res.text)) continue;
            const locs = [...res.text.matchAll(/<loc>\s*(?:<!\[CDATA\[)?\s*([^<\]]+?)\s*(?:\]\]>)?\s*<\/loc>/gi)].map(m => m[1]);
            const isIndex = /<sitemapindex/i.test(res.text);
            return {
                found: true, source: src, urlCount: isIndex ? 0 : locs.length,
                sample: isIndex ? [] : locs.slice(0, 50), nestedSitemaps: isIndex ? locs.slice(0, 50) : [],
            };
        } catch { /* try next */ }
    }
    return { found: false, urlCount: 0, sample: [], nestedSitemaps: [] };
}

export async function securityTxtIntel(origin: string): Promise<SecurityTxt> {
    for (const path of ['/.well-known/security.txt', '/security.txt']) {
        try {
            const res = await safeFetch(origin + path, { timeoutMs: 8000, maxBytes: 64 * 1024, accept: 'text/plain' });
            if (res.status !== 200 || !/contact\s*:/i.test(res.text) || /<html/i.test(res.text.slice(0, 300))) continue;
            const field = (f: string) => [...res.text.matchAll(new RegExp(`^${f}\\s*:\\s*(.+)$`, 'gim'))].map(m => m[1].trim());
            return { found: true, url: origin + path, contact: field('Contact'), policy: field('Policy'), expires: field('Expires')[0] };
        } catch { /* next */ }
    }
    return { found: false, contact: [], policy: [] };
}

let lastCrtSh = 0;
export async function ctIntel(apex: string, enabled: boolean): Promise<CTIntel> {
    if (!enabled) return { enabled: false, subdomains: [], certCount: 0 };
    return cached(`ct:${apex}`, 60 * 60_000, async () => {
        const gap = lastCrtSh + 3000 - Date.now(); // global politeness to crt.sh
        if (gap > 0) await new Promise(r => setTimeout(r, gap));
        lastCrtSh = Date.now();
        try {
            const q = `https://crt.sh/?q=${encodeURIComponent('%.' + apex)}&output=json&exclude=expired`;
            const rows = await fetchPublicJson<{ name_value: string }[]>(q, 25000)
                .catch(async () => { await new Promise(r => setTimeout(r, 2500)); return fetchPublicJson<{ name_value: string }[]>(q, 30000); });
            const subs = new Set<string>();
            rows.forEach(r => r.name_value.split('\n').forEach(n => {
                const h = n.trim().toLowerCase().replace(/^\*\./, '');
                if (h.endsWith(apex) && /^[a-z0-9.-]+$/.test(h)) subs.add(h);
            }));
            return { enabled: true, subdomains: [...subs].sort().slice(0, 500), certCount: rows.length };
        } catch (e: any) {
            return { enabled: true, subdomains: [], certCount: 0, error: `crt.sh unavailable (${e?.message || 'error'}) — public CT service is often rate-limited; retry later.` };
        }
    });
}

export async function waybackIntel(host: string, enabled: boolean): Promise<WaybackIntel> {
    if (!enabled) return { enabled: false, available: false };
    return cached(`wb:${host}`, 60 * 60_000, async () => {
        try {
            await politeDelay('archive.org', 1000);
            const [avail, first, count] = await Promise.allSettled([
                fetchPublicJson<any>(`https://archive.org/wayback/available?url=${encodeURIComponent(host)}`, 15000),
                fetchPublicJson<any[]>(`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(host)}&output=json&limit=1&fl=timestamp`, 20000),
                fetchPublicJson<any[]>(`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(host)}&output=json&fl=timestamp&collapse=timestamp:6&limit=2000`, 20000),
            ]);
            if (avail.status === 'rejected') console.warn('[wayback] available API:', avail.reason?.message);
            const closest = avail.status === 'fulfilled' ? avail.value?.archived_snapshots?.closest : undefined;
            const ts = first.status === 'fulfilled' ? first.value?.[1]?.[0] : undefined;
            const fmt = (t?: string) => t ? `${t.slice(0, 4)}-${t.slice(4, 6)}-${t.slice(6, 8)}` : undefined;
            return {
                enabled: true,
                available: !!closest?.available,
                closestUrl: closest?.url,
                closestTimestamp: fmt(closest?.timestamp),
                firstSeen: fmt(ts),
                snapshotCount: count.status === 'fulfilled' && Array.isArray(count.value) ? Math.max(0, count.value.length - 1) : undefined,
            };
        } catch (e: any) {
            return { enabled: true, available: false, error: e?.message || 'Wayback lookup failed' };
        }
    });
}
