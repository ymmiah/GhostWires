// GhostWires Mk.IV — deterministic OSINT pipeline orchestrator
import type { ReconReport, CrawlResult, CrawlPage } from '../types';
import { normalizeTarget, safeFetch, registrableDomain, politeDelay, TargetError } from './net';
import { dnsIntel } from './dnsIntel';
import { tlsIntel } from './tlsIntel';
import { auditHeaders } from './headersAudit';
import { fingerprint } from './fingerprint';
import { parseHtml } from './htmlIntel';
import { robotsIntel, robotsAllows, sitemapIntel, securityTxtIntel, ctIntel, waybackIntel } from './surfaceIntel';

export const ENGINE = 'GhostWires Mk.IV';
export const VERSION = '4.0.0';

export interface ReconOptions { ct?: boolean; wayback?: boolean; }

export async function runRecon(input: string, opts: ReconOptions = {}): Promise<ReconReport> {
    const started = Date.now();
    const url = normalizeTarget(input);
    const notes: string[] = [];

    // Robots first, so we can honour it for the primary page too.
    const robots = await robotsIntel(url.origin);
    if (!robotsAllows(robots, url.pathname)) {
        notes.push(`robots.txt disallows ${url.pathname} for generic crawlers — fetched once for passive analysis only; deep crawl will skip it.`);
    }

    const page = await safeFetch(url, { timeoutMs: 20000 });
    const final = new URL(page.url);
    const apex = registrableDomain(final.hostname);
    const contentType = page.headers.get('content-type') || '';
    const html = /html|xml|text/i.test(contentType) || !contentType ? page.text : '';
    if (!html) notes.push(`Target returned non-HTML content (${contentType}); HTML modules skipped.`);
    if (page.status >= 400) notes.push(`Target responded with HTTP ${page.status}; results may reflect an error page or bot challenge.`);

    const parsed = parseHtml(html || '<html></html>', final.href);

    const [dns, tls, sitemap, securityTxt, ct, wayback] = await Promise.all([
        dnsIntel(final.hostname, apex),
        final.protocol === 'https:' ? tlsIntel(final.hostname, page.resolvedIPs[0], Number(final.port) || 443) : Promise.resolve({ available: false, sans: [], error: 'Target is plain HTTP' }),
        sitemapIntel(final.origin, robots),
        securityTxtIntel(final.origin),
        ctIntel(apex, opts.ct !== false),
        waybackIntel(final.hostname, opts.wayback !== false),
    ]);

    return {
        engine: `${ENGINE} v${VERSION}`,
        generatedAt: new Date().toISOString(),
        durationMs: Date.now() - started,
        target: {
            input, url: url.href, finalUrl: final.href, hostname: final.hostname, registrableDomain: apex,
            status: page.status, contentType, bytes: page.body.length, responseTimeMs: page.timeMs,
            redirectChain: page.redirectChain, resolvedIPs: page.resolvedIPs,
        },
        dns, tls,
        headers: auditHeaders(page.headers, page.setCookies, final.protocol === 'https:'),
        tech: fingerprint(html, page.headers, page.setCookies, parsed.scripts, parsed.meta.generator),
        contacts: parsed.contacts,
        meta: parsed.meta,
        links: parsed.links,
        images: parsed.images,
        subfolders: parsed.subfolders,
        forms: parsed.forms,
        accessibility: parsed.accessibility,
        robots, sitemap, securityTxt, ct, wayback, notes,
    };
}

/** Polite breadth-first crawl of same-host pages. Honours robots.txt + crawl-delay. */
export async function runCrawl(input: string, maxPages = 12, maxDepth = 2): Promise<CrawlResult> {
    const start = normalizeTarget(input);
    const robots = await robotsIntel(start.origin);
    const gap = Math.min(Math.max((robots.crawlDelay || 0) * 1000, 750), 5000);
    const limit = Math.min(Math.max(maxPages, 1), 25);
    const queue: { url: string; depth: number; from?: string }[] = [{ url: start.href, depth: 0 }];
    const visited = new Set<string>();
    const pages: CrawlPage[] = [];
    const skippedByRobots: string[] = [];
    const edges: [string, string][] = [];

    while (queue.length && pages.length < limit) {
        const { url, depth, from } = queue.shift()!;
        if (visited.has(url)) continue;
        visited.add(url);
        const u = new URL(url);
        if (!robotsAllows(robots, u.pathname)) { skippedByRobots.push(url); continue; }
        if (/\.(pdf|jpe?g|png|gif|svg|webp|zip|mp4|mp3|css|js|xml|ico|woff2?)$/i.test(u.pathname)) continue;
        if (from) edges.push([from, url]);
        await politeDelay(u.host, gap);
        try {
            const res = await safeFetch(u, { timeoutMs: 12000, maxBytes: 2 * 1024 * 1024 });
            const final = new URL(res.url);
            if (final.host !== start.host) { pages.push({ url, status: res.status, title: '(redirected off-host)', description: res.url, wordCount: 0, depth, outLinks: 0, emails: [] }); continue; }
            const parsed = parseHtml(res.text, res.url);
            const internal = parsed.links.filter(l => l.type === 'internal' && new URL(l.href).host === start.host);
            pages.push({
                url, status: res.status, title: parsed.meta.title || '(untitled)', description: parsed.meta.description,
                wordCount: parsed.meta.wordCount, depth, outLinks: parsed.links.length, emails: parsed.contacts.emails,
            });
            if (depth < maxDepth) for (const l of internal) {
                const n = new URL(l.href); n.search = ''; n.hash = '';
                if (!visited.has(n.href)) queue.push({ url: n.href, depth: depth + 1, from: url });
            }
        } catch (e: any) {
            pages.push({ url, status: e instanceof TargetError ? e.status : 0, title: '(fetch failed)', description: '', wordCount: 0, depth, outLinks: 0, emails: [], error: e?.message });
        }
    }
    return { pages, skippedByRobots, edges };
}
