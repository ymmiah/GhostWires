// GhostWires Mk.IV — hardened outbound networking (SSRF guard + bounded fetch)
import dns from 'node:dns/promises';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import { createGunzip, createInflate, createBrotliDecompress } from 'node:zlib';
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
    ['2001:db8::', 32], ['100::', 64], ['2001::', 23], ['2002::', 16], ['3fff::', 20],
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
    if (net.isIP(ip) === 6) ip = new URL(`http://[${ip}]/`).hostname.slice(1, -1);
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
        // Permit conventional global unicast only; block transition mechanisms
        // which can encode an unchecked IPv4 destination (Teredo, 6to4, NAT64).
        if (!/^[23][0-9a-f]{3}:/.test(lower)) return true;
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
    if (BLOCKED_HOSTNAMES.some(r => r.test(u.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '')))) throw new TargetError('Internal hostnames are blocked.', 403);
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
        let timer: ReturnType<typeof setTimeout>;
        try {
            addrs = await Promise.race([dns.lookup(host, { all: true, verbatim: true }), new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('DNS timeout')), 5000); })]);
        } finally { clearTimeout(timer!); }
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
    truncated?: boolean;
}

export interface SafeFetchOptions {
    timeoutMs?: number;
    maxBytes?: number;
    maxRedirects?: number;
    accept?: string;
    method?: 'GET' | 'HEAD';
    sameOrigin?: string;
    signal?: AbortSignal;
}

/** The socket resolver can return only addresses already checked by assertPublicHost. */
export function pinnedLookup(addresses: string[]) {
    return (_host: string, options: any, callback: (...args: any[]) => void) => {
        const family = typeof options === 'number' ? options : options?.family;
        const candidates = addresses.filter(ip => !isBlockedIP(ip) && (!family || net.isIP(ip) === family));
        if (!candidates.length) return callback(new TargetError('No validated address available.', 403));
        if (options?.all) return callback(null, candidates.map(address => ({ address, family: net.isIP(address) })));
        callback(null, candidates[0], net.isIP(candidates[0]));
    };
}

async function requestHop(url: URL, addresses: string[], opts: SafeFetchOptions, signal: AbortSignal): Promise<SafeResponse> {
    const started = Date.now();
    return new Promise((resolve, reject) => {
        const transport = url.protocol === 'https:' ? https : http;
        const req = transport.request(url, {
            method: opts.method || 'GET', agent: false, signal,
            lookup: pinnedLookup(addresses),
            headers: { 'User-Agent': USER_AGENT, Accept: opts.accept || 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-GB,en;q=0.9', 'Accept-Encoding': 'gzip, deflate, br' },
        }, res => {
            const headers = new Headers();
            for (const [name, value] of Object.entries(res.headers)) for (const v of Array.isArray(value) ? value : value === undefined ? [] : [value]) headers.append(name, v);
            const result = (body: Buffer, truncated = false): SafeResponse => ({ url: url.href, status: res.statusCode || 0, headers, setCookies: res.headers['set-cookie'] || [], body, text: body.toString('utf8'), redirectChain: [], resolvedIPs: addresses, timeMs: Date.now() - started, truncated });
            if ((res.statusCode! >= 300 && res.statusCode! < 400 && headers.has('location')) || opts.method === 'HEAD') { res.destroy(); resolve(result(Buffer.alloc(0))); return; }
            const encoding = res.headers['content-encoding'];
            const decoder = encoding === 'gzip' ? createGunzip() : encoding === 'deflate' ? createInflate() : encoding === 'br' ? createBrotliDecompress() : undefined;
            if (encoding && encoding !== 'identity' && !decoder) { res.destroy(); reject(new TargetError('Unsupported response encoding.', 502)); return; }
            const stream = decoder ? res.pipe(decoder) : res;
            const chunks: Buffer[] = [];
            const cap = opts.maxBytes ?? 3 * 1024 * 1024;
            let total = 0, compressed = 0, settled = false;
            const finish = (truncated: boolean) => {
                if (settled) return;
                settled = true;
                resolve(result(Buffer.concat(chunks), truncated));
                if (truncated) { stream.destroy(); res.destroy(); req.destroy(); }
            };
            res.on('data', chunk => { compressed += chunk.length; if (compressed > cap * 2) finish(true); });
            stream.on('data', (chunk: Buffer) => {
                if (settled) return;
                const remaining = cap - total;
                chunks.push(chunk.subarray(0, remaining)); total += Math.min(chunk.length, remaining);
                if (chunk.length > remaining) finish(true);
            });
            stream.on('end', () => finish(false));
            const fail = () => { if (!settled) { settled = true; stream.destroy(); res.destroy(); reject(new TargetError('Response interrupted before completion.', 502)); } };
            stream.on('error', fail); res.on('error', fail); res.on('aborted', fail);
        });
        req.on('error', error => reject(error));
        req.end();
    });
}

/**
 * Fetch a public URL with: SSRF validation on every hop, manual redirects,
 * timeout, and a hard response-size cap.
 */
export async function safeFetch(target: string | URL, opts: SafeFetchOptions = {}): Promise<SafeResponse> {
    const { timeoutMs = 15000, maxRedirects = 5 } = opts;
    let current = normalizeTarget(typeof target === 'string' ? target : target.href);
    const chain: RedirectHop[] = [];
    const started = Date.now();
    const controller = new AbortController();
    const cancel = () => controller.abort();
    opts.signal?.addEventListener('abort', cancel, { once: true });
    if (opts.signal?.aborted) controller.abort();
    const timer = setTimeout(cancel, timeoutMs);
    try {
        for (let hop = 0; hop <= maxRedirects; hop++) {
            if (controller.signal.aborted) throw new TargetError('Request cancelled or timed out.', 504);
            if (opts.sameOrigin && current.origin !== opts.sameOrigin) throw new TargetError('Redirect left the approved origin.', 403);
            const addresses = await assertPublicHost(current.hostname);
            const res = await requestHop(current, addresses, opts, controller.signal);
            if (res.status >= 300 && res.status < 400 && res.headers.has('location')) {
                chain.push({ url: current.href, status: res.status });
                current = normalizeTarget(new URL(res.headers.get('location')!, current).href);
                continue;
            }
            return { ...res, redirectChain: chain, timeMs: Date.now() - started };
        }
        throw new TargetError(`Too many redirects (>${maxRedirects})`, 508);
    } catch (error: any) {
        if (controller.signal.aborted) throw new TargetError('Request cancelled or timed out.', 504);
        if (error instanceof TargetError) throw error;
        throw new TargetError(`Fetch failed: ${error?.code || 'network error'}`, 502);
    } finally { clearTimeout(timer); opts.signal?.removeEventListener('abort', cancel); }
}

/** Fetch a JSON document from a fixed public API (crt.sh, archive.org …). */
export async function fetchPublicJson<T = any>(url: string, timeoutMs = 15000): Promise<T> {
    const res = await safeFetch(url, { timeoutMs, accept: 'application/json', maxBytes: 8 * 1024 * 1024 });
    if (res.status !== 200 || res.truncated) throw new Error(`HTTP ${res.status} or incomplete JSON response`);
    return JSON.parse(res.text) as T;
}

/** Tiny per-host politeness gate so crawls never hammer a target. */
const lastHit = new Map<string, number>();
export async function politeDelay(host: string, minGapMs = 600) {
    const now = Date.now();
    if (lastHit.size > 1000) for (const [key, at] of lastHit) if (at < now - 60_000) lastHit.delete(key);
    const at = Math.max(now, (lastHit.get(host) || 0) + minGapMs);
    lastHit.set(host, at);
    const wait = at - now;
    if (wait > 0) await new Promise(r => setTimeout(r, wait));
}

export function registrableDomain(hostname: string): string {
    const parts = hostname.toLowerCase().replace(/^www\./, '').split('.');
    if (parts.length <= 2) return parts.join('.');
    const sld2 = ['co', 'com', 'org', 'net', 'ac', 'gov', 'edu', 'ltd', 'plc', 'me', 'sch', 'nhs'];
    if (parts[parts.length - 1].length === 2 && sld2.includes(parts[parts.length - 2])) return parts.slice(-3).join('.');
    return parts.slice(-2).join('.');
}
