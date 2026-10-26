// GhostWires Mk.IV — hardened outbound networking (SSRF guard + bounded fetch)
import dns from 'node:dns/promises';
import net from 'node:net';
import type { RedirectHop } from '../types';

export const USER_AGENT =
    'Mozilla/5.0 (compatible; GhostWires-MkIV/4.0; +https://github.com/ymmiah/GhostWires; authorized-OSINT)';

// IMPORTANT: keep IPv4 and IPv6 in SEPARATE BlockLists.
// Node's net.BlockList mixes families poorly — adding ::ffff:0:0/96 to a shared
// list makes check("148.x.x.x", "ipv4") return true for every public IPv4.
const v4Block = new net.BlockList();
const v6Block = new net.BlockList();

// IPv4 private / reserved / special-purpose ranges
[
    ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
    ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
    ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
    ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
].forEach(([a, p]) => v4Block.addSubnet(a as string, p as number, 'ipv4'));

// IPv6 loopback / unspecified / ULA / link-local / multicast / docs / discard
// Do NOT add ::ffff:0:0/96 here — that is the entire IPv4 space; handle mapped below.
[
    ['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
    ['2001:db8::', 32], ['100::', 64],
].forEach(([a, p]) => v6Block.addSubnet(a as string, p as number, 'ipv6'));

// Some VPN/TUN proxies (e.g. Clash "fake-ip" mode) answer DNS with 198.18.0.0/15.
// Opt-in only: GHOSTWIRES_ALLOW_FAKEIP=1 lets those through. Never enable on shared servers.
const allowFakeIP = () => process.env.GHOSTWIRES_ALLOW_FAKEIP === '1';
const fakeIPRange = new net.BlockList();
fakeIPRange.addSubnet('198.18.0.0', 15, 'ipv4');

/** Turn two hextets into dotted IPv4. */
function hextetsToIPv4(hiHex: string, loHex: string): string {
    const hi = parseInt(hiHex, 16);
    const lo = parseInt(loHex, 16);
    return `${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`;
}

/** Extract embedded IPv4 from IPv4-mapped (::ffff:…) or NAT64 64:ff9b::/96. */
function embeddedIPv4(ip: string): string | null {
    const lower = ip.toLowerCase();
    const dotted = lower.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (dotted) return dotted[1];
    const hexMapped = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hexMapped) return hextetsToIPv4(hexMapped[1], hexMapped[2]);
    // NAT64 well-known prefix — last 32 bits are the IPv4 address
    const nat64 = lower.match(/^64:ff9b:(?:0:){0,4}([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (nat64) return hextetsToIPv4(nat64[1], nat64[2]);
    if (lower === '64:ff9b::' || lower.startsWith('64:ff9b::')) {
        // 64:ff9b::a.b.c.d dotted form
        const natDotted = lower.match(/^64:ff9b::(\d{1,3}(?:\.\d{1,3}){3})$/);
        if (natDotted) return natDotted[1];
    }
    return null;
}

export function isBlockedIP(ip: string): boolean {
    const family = net.isIP(ip);
    if (family === 4) {
        if (allowFakeIP() && fakeIPRange.check(ip, 'ipv4')) return false;
        return v4Block.check(ip, 'ipv4');
    }
    if (family === 6) {
        const embedded = embeddedIPv4(ip);
        if (embedded) {
            if (allowFakeIP() && fakeIPRange.check(embedded, 'ipv4')) return false;
            return v4Block.check(embedded, 'ipv4');
        }
        // Unparsed NAT64 → block (avoid treating the whole prefix as public)
        const lower = ip.toLowerCase();
        if (lower === '64:ff9b::' || lower.startsWith('64:ff9b:')) return true;
        return v6Block.check(lower, 'ipv6');
    }
    return true;
}

const BLOCKED_HOSTNAMES = [/^localhost$/i, /\.localhost$/i, /\.local$/i, /\.internal$/i, /^metadata(\.google\.internal)?$/i];

export class TargetError extends Error {
    constructor(message: string, public status = 400) { super(message); }
}

export function normalizeTarget(input: string): URL {
    let raw = (input || '').trim();
    if (!raw) throw new TargetError('Missing target URL.');
    if (raw.length > 2048) throw new TargetError('Target URL too long.');
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = `https://${raw}`;
    let u: URL;
    try { u = new URL(raw); } catch { throw new TargetError('Invalid target URL format.'); }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new TargetError('Only http(s) targets are allowed.');
    if (u.username || u.password) throw new TargetError('Credentials in URLs are not allowed.');
    if (u.port && !['80', '443', '8080', '8443'].includes(u.port)) throw new TargetError('Non-standard ports are blocked.');
    u.hash = '';
    return u;
}

/** Resolve the hostname and refuse anything that lands on a private / internal address. */
export async function assertPublicHost(hostname: string): Promise<string[]> {
    const host = hostname.replace(/^\[|\]$/g, '');
    if (BLOCKED_HOSTNAMES.some(r => r.test(host))) throw new TargetError(`Blocked host: ${host}`, 403);
    if (net.isIP(host)) {
        if (isBlockedIP(host)) throw new TargetError(`Blocked private/reserved address: ${host}`, 403);
        return [host];
    }
    let addrs: { address: string }[];
    try {
        addrs = await dns.lookup(host, { all: true, verbatim: true });
    } catch {
        throw new TargetError(`DNS resolution failed for ${host}`, 502);
    }
    if (!addrs.length) throw new TargetError(`No addresses for ${host}`, 502);
    const bad = addrs.find(a => isBlockedIP(a.address));
    if (bad) throw new TargetError(`Blocked: ${host} resolves to private/reserved address ${bad.address}`, 403);
    return addrs.map(a => a.address);
}

export interface SafeResponse {
    url: string;
    status: number;
    headers: Headers;
    setCookies: string[];
    body: Buffer;
    text: string;
    redirectChain: RedirectHop[];
    resolvedIPs: string[];
    timeMs: number;
}

export interface SafeFetchOptions {
    timeoutMs?: number;
    maxBytes?: number;
    maxRedirects?: number;
    accept?: string;
    method?: 'GET' | 'HEAD';
}

/**
 * Fetch a public URL with: SSRF validation on every hop, manual redirects,
 * timeout, and a hard response-size cap.
 */
export async function safeFetch(target: string | URL, opts: SafeFetchOptions = {}): Promise<SafeResponse> {
    const { timeoutMs = 15000, maxBytes = 3 * 1024 * 1024, maxRedirects = 5, accept, method = 'GET' } = opts;
    let current = typeof target === 'string' ? normalizeTarget(target) : target;
    const chain: RedirectHop[] = [];
    const started = Date.now();
    let resolvedIPs: string[] = [];

    for (let hop = 0; hop <= maxRedirects; hop++) {
        resolvedIPs = await assertPublicHost(current.hostname);
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        let res: Response;
        try {
            res = await fetch(current, {
                method,
                redirect: 'manual',
                signal: controller.signal,
                headers: {
                    'User-Agent': USER_AGENT,
                    Accept: accept || 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-GB,en;q=0.9',
                },
            });
        } catch (e: any) {
            clearTimeout(timer);
            if (e?.name === 'AbortError') throw new TargetError(`Timed out after ${timeoutMs / 1000}s fetching ${current.href}`, 504);
            throw new TargetError(`Fetch failed for ${current.href}: ${e?.cause?.code || e?.message || 'network error'}`, 502);
        }

        if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
            clearTimeout(timer);
            chain.push({ url: current.href, status: res.status });
            const next = new URL(res.headers.get('location')!, current);
            current = normalizeTarget(next.href);
            continue;
        }

        // Stream body with size cap
        const chunks: Buffer[] = [];
        let total = 0;
        try {
            if (res.body && method === 'GET') {
                const reader = res.body.getReader();
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    total += value.byteLength;
                    if (total > maxBytes) { controller.abort(); break; }
                    chunks.push(Buffer.from(value));
                }
            }
        } catch { /* truncated */ } finally { clearTimeout(timer); }
        const body = Buffer.concat(chunks);
        const setCookies = typeof (res.headers as any).getSetCookie === 'function' ? (res.headers as any).getSetCookie() : [];
        return {
            url: current.href, status: res.status, headers: res.headers, setCookies, body,
            text: body.toString('utf8'), redirectChain: chain, resolvedIPs, timeMs: Date.now() - started,
        };
    }
    throw new TargetError(`Too many redirects (>${maxRedirects})`, 508);
}

/** Fetch a JSON document from a fixed public API (crt.sh, archive.org …). */
export async function fetchPublicJson<T = any>(url: string, timeoutMs = 15000): Promise<T> {
    const res = await safeFetch(url, { timeoutMs, accept: 'application/json', maxBytes: 8 * 1024 * 1024 });
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    return JSON.parse(res.text) as T;
}

/** Tiny per-host politeness gate so crawls never hammer a target. */
const lastHit = new Map<string, number>();
export async function politeDelay(host: string, minGapMs = 600) {
    const now = Date.now();
    const wait = (lastHit.get(host) || 0) + minGapMs - now;
    if (wait > 0) await new Promise(r => setTimeout(r, wait));
    lastHit.set(host, Date.now());
}

export function registrableDomain(hostname: string): string {
    const parts = hostname.toLowerCase().replace(/^www\./, '').split('.');
    if (parts.length <= 2) return parts.join('.');
    const sld2 = ['co', 'com', 'org', 'net', 'ac', 'gov', 'edu', 'ltd', 'plc', 'me', 'sch', 'nhs'];
    if (parts[parts.length - 1].length === 2 && sld2.includes(parts[parts.length - 2])) return parts.slice(-3).join('.');
    return parts.slice(-2).join('.');
}
