import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fingerprint, mergeAssetVersions } from '../server/fingerprint';
import { affectedProduct, TechnologyAdvisoryClient } from '../server/assessment/technologyAdvisories';
import type { SafeResponse } from '../server/net';
import type { TechHit } from '../types';
const NOW = '2026-11-03T12:00:00Z';
const tech = (name = 'PHP', version?: string): TechHit => ({ name, version, category: 'Language', evidence: `header: ${name}/${version || 'unknown'}` });
const response = (data: unknown, status = 200): SafeResponse => { const text = JSON.stringify(data); return { url: 'https://services.nvd.nist.gov/', status, headers: new Headers(), setCookies: [], body: Buffer.from(text), text, redirectChain: [], resolvedIPs: [], timeMs: 1 }; };
const config = (extra = {}, product = 'php:php') => [{ nodes: [{ operator: 'OR', cpeMatch: [{ vulnerable: true, criteria: `cpe:2.3:a:${product}:*:*:*:*:*:*:*:*`, versionStartIncluding: '8.1.0', versionEndExcluding: '8.1.3', ...extra }] }] }];
const record = (extra = {}) => ({ cve: { id: 'CVE-2026-12345', vulnStatus: 'Analyzed', configurations: config(), descriptions: [{ lang: 'en', value: 'Synthetic advisory fixture, not a real vulnerability claim.' }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: 7.5 } }] }, ...extra } });
const feed = (rows = [record()], extra = {}) => ({ startIndex: 0, totalResults: rows.length, vulnerabilities: rows, ...extra });
const client = (fetcher: any) => new TechnologyAdvisoryClient(fetcher, () => Date.parse(NOW), async () => {});

test('technology results differ by site and bind versions to product-specific evidence', () => {
    const wp = fingerprint('<script src="/wp-content/plugins/woocommerce/js/cart.js?ver=9.1.0"></script><link href="/wp-content/themes/store/style.css?ver=2.0.0">', new Headers({ 'x-powered-by': 'PHP/8.1.2' }), [], [], 'WordPress 6.6.2');
    assert.equal(wp.find(t => t.name === 'WordPress')?.version, '6.6.2');
    assert.equal(wp.find(t => t.name === 'PHP')?.version, '8.1.2');
    assert.ok(wp.some(t => t.name === 'WordPress plugin: woocommerce'));
    assert.ok(wp.some(t => t.name === 'WordPress theme: store'));
    assert.equal(wp.find(t => t.name === 'WordPress plugin: woocommerce')?.version, undefined);
    assert.deepEqual(wp.find(t => t.name === 'WordPress plugin: woocommerce')?.versionHints, ['9.1.0']);
    const next = fingerprint('<script src="/_next/static/main.js"></script><p>WordPress 1.2.3 PHP/5.0.0</p>', new Headers({ server: 'Vercel' }), [], ['/_next/static/main.js'], '');
    assert.ok(next.some(t => t.name === 'Next.js'));
    assert.ok(!next.some(t => t.name === 'PHP' || t.name === 'WordPress'));
});

test('generic cache versions, hidden versions, prereleases and quoted versions do not become exact claims', () => {
    const hits = fingerprint('<div>WordPress 1.2.3</div><script src="/wp-includes/main.js?ver=9.9.9"></script>', new Headers(), [], ['/wp-includes/main.js?ver=9.9.9', '/jquery-3.7.1-beta.js', '/jquery-3.7.1.2.js'], '');
    assert.equal(hits.find(t => t.name === 'WordPress')?.version, undefined);
    assert.equal(hits.find(t => t.name === 'jQuery')?.version, undefined);
    assert.equal(mergeAssetVersions([], '/*! jQuery v3.7.1-beta */', 'https://example.com/a.js').length, 0);
});

test('library asset URLs and banners identify versions; contradictory claims disable exact matching', () => {
    let hits = fingerprint('', new Headers(), [], ['https://cdn.example.com/jquery@3.7.1/dist/jquery.min.js'], '');
    assert.equal(hits.find(t => t.name === 'jQuery')?.version, '3.7.1');
    hits = mergeAssetVersions(hits, '/*! jQuery v3.6.0 */', 'https://example.com/jquery.js');
    assert.equal(hits[0].version, undefined);
    assert.deepEqual(hits[0].versionCandidates, ['3.7.1', '3.6.0']);
    assert.equal(hits[0].confidence, 'low');
});

test('NVD affected-product matching respects identity, boundaries, vulnerable flags and qualifiers', () => {
    assert.equal(affectedProduct(config(), 'php', 'php', '8.1.2'), true);
    assert.equal(affectedProduct(config(), 'php', 'php', '8.1.3'), false);
    assert.equal(affectedProduct(config({ vulnerable: false }), 'php', 'php', '8.1.2'), false);
    assert.equal(affectedProduct(config({}, 'other:php'), 'php', 'php', '8.1.2'), false);
    assert.equal(affectedProduct(config({ versionEndExcluding: '8.x' }), 'php', 'php', '8.1.2'), false);
    assert.equal(affectedProduct(config({ criteria: 'cpe:2.3:a:php:php:8.1.2:rc1:*:*:*:*:*:*' }), 'php', 'php', '8.1.2'), false);
    assert.equal(affectedProduct([{ negate: true, nodes: (config()[0] as any).nodes }], 'php', 'php', '8.1.2'), false);
});

test('exact CVE candidates have evidence, uncertainty and NVD links without disclosing target URLs', async () => {
    let calls = 0;
    const c = client(async (url: URL, opts: any) => {
        calls++; assert.equal(url.hostname, 'services.nvd.nist.gov');
        assert.equal(url.searchParams.get('cpeName'), 'cpe:2.3:a:php:php:8.1.2:*:*:*:*:*:*:*');
        assert.ok(!String(url).includes('private-target.example'));
        assert.equal(opts.maxRedirects, 0); return response(feed());
    });
    const r = await c.assess([tech('PHP', '8.1.2')], 'https://private-target.example', NOW);
    assert.equal(r.checks[0].status, 'matched'); assert.equal(r.findings.length, 1);
    assert.equal(r.findings[0].status, 'potential-vulnerability');
    assert.equal(r.findings[0].severity, 'high');
    assert.equal(r.findings[0].advisory?.knownExploited, null);
    assert.ok(r.findings[0].limitations.some(l => /backports/.test(l)));
    await c.assess([tech('PHP', '8.1.2')], 'https://another.example', NOW);
    assert.equal(calls, 1);
});

test('unknown/conflicting/unsupported versions get research links and never make feed requests', async () => {
    const c = client(async () => { throw new Error('Must not request'); });
    const r = await c.assess([tech(), tech('PHP', '8.1'), tech('Cloudflare'), { ...tech('PHP', '8.1.2'), versionCandidates: ['8.1.2', '8.1.3'] }], 'https://example.com', NOW);
    assert.deepEqual(r.checks.map(c => c.status), ['unknown-version', 'unknown-version', 'conflicting-version', 'unsupported']);
    assert.equal(r.findings.length, 0); assert.ok(r.checks.every(c => c.searchUrl.startsWith('https://nvd.nist.gov/')));
});

test('rate limits, bad feeds, missing configurations and pagination stay incomplete', async () => {
    for (const data of [{}, feed([], { startIndex: 1 })]) {
        const r = await client(async () => response(data)).assess([tech('PHP', '8.1.2')], 'https://example.com', NOW);
        assert.equal(r.checks[0].status, 'unavailable');
    }
    const partial = await client(async () => response(feed([record()], { totalResults: 101 }))).assess([tech('PHP', '8.1.2')], 'https://example.com', NOW);
    assert.equal(partial.checks[0].status, 'partial'); assert.equal(partial.findings.length, 1);
    const invalid = await client(async () => response(feed([record({ configurations: undefined })]))).assess([tech('PHP', '8.1.2')], 'https://example.com', NOW);
    assert.equal(invalid.checks[0].status, 'partial');
    const unavailable = await client(async () => response({}, 429)).assess([tech('PHP', '8.1.2')], 'https://example.com', NOW);
    assert.equal(unavailable.checks[0].status, 'unavailable');
});

test('no affected version does not create a CVE; product budget and concurrent refreshes are bounded', async () => {
    let calls = 0;
    const c = client(async () => { calls++; return response(feed([])); });
    const both = await Promise.all([c.assess([tech('PHP', '8.1.4')], 'https://one.example', NOW), c.assess([tech('PHP', '8.1.4')], 'https://two.example', NOW)]);
    assert.equal(calls, 1); assert.equal(both[0].checks[0].status, 'no-match'); assert.equal(both[0].findings.length, 0);
    const r = await c.assess(['PHP', 'WordPress', 'Apache', 'jQuery'].map(n => tech(n, '1.2.3')), 'https://example.com', NOW);
    assert.equal(calls, 4); assert.equal(r.checks[3].status, 'partial');
});

test('cancelled assessments make no advisory request', async () => {
    const ac = new AbortController(); ac.abort();
    await assert.rejects(client(async () => { throw new Error('Must not fetch'); }).assess([tech('PHP', '8.1.2')], 'https://example.com', NOW, ac.signal), /cancelled/);
});
