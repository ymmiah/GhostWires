import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KevClient } from '../server/assessment/kev';
import { groupFindings } from '../server/assessment/groups';
import type { SafeResponse } from '../server/net';
import { assessment } from './fixtures/assessment';

const NOW = Date.parse('2026-11-03T12:00:00Z');
const entry = { cveID: 'CVE-2026-12345', dateAdded: '2026-11-02', requiredAction: 'Apply the vendor fix.', knownRansomwareCampaignUse: 'Unknown' };
const response = (data: unknown, status = 200): SafeResponse => { const text = JSON.stringify(data); return { url: 'https://www.cisa.gov/', status, headers: new Headers(), setCookies: [], body: Buffer.from(text), text, redirectChain: [], resolvedIPs: [], timeMs: 1 }; };
const catalogue = () => ({ catalogVersion: '2026.11.03', dateReleased: '2026-11-03T00:00:00Z', count: 1, vulnerabilities: [entry] });

test('KEV enrichment requires an exact matched CVE and never raises severity', async () => {
    const a = assessment();
    const client = new KevClient(async () => response(catalogue()), () => NOW);
    await client.enrich(a);
    assert.equal(a.threatIntelligence?.status, 'current');
    assert.equal(a.findings[0].advisory?.knownExploited, true);
    assert.equal(a.findings[0].severity, 'high');
    assert.ok(a.findings[0].limitations.some(l => /does not establish exploitation/.test(l)));
    const unrelated = assessment('CVE-2026-123456');
    await client.enrich(unrelated);
    assert.equal(unrelated.findings[0].advisory?.knownExploited, false);
    assert.ok(!unrelated.findings[0].advisory?.kev);
});

test('no CVE means no feed request or inference from a PHP product name', async () => {
    const a = assessment(); delete a.findings[0].advisory;
    a.findings[0].title = 'PHP';
    await new KevClient(async () => { throw new Error('Must not fetch'); }).enrich(a);
    assert.equal(a.threatIntelligence?.status, 'not-requested');
});

test('KEV uses only the canonical feed and official mirror, sharing concurrent refreshes', async () => {
    const sources: string[] = [];
    const client = new KevClient(async (url, opts) => { sources.push(String(url)); assert.equal(opts?.maxRedirects, 0); return sources.length === 1 ? response({}, 403) : response(catalogue()); }, () => NOW);
    const a = assessment(), b = assessment();
    await Promise.all([client.enrich(a), client.enrich(b)]);
    assert.equal(sources.length, 2);
    assert.match(sources[1], /^https:\/\/raw.githubusercontent.com\/cisagov\/kev-data\//);
    assert.equal(a.findings[0].advisory?.knownExploited, true);
    assert.equal(b.findings[0].advisory?.knownExploited, true);
});

test('invalid/empty/truncated KEV responses remain unavailable instead of clearing risk', async () => {
    for (const data of [{}, { ...catalogue(), count: 0, vulnerabilities: [] }, { ...catalogue(), count: 2 }, { ...catalogue(), vulnerabilities: [{ cveID: 'invalid' }] }]) {
        const a = assessment();
        await new KevClient(async () => response(data), () => NOW).enrich(a);
        assert.equal(a.threatIntelligence?.status, 'unavailable');
        assert.equal(a.findings[0].advisory?.knownExploited, null);
    }
    const a = assessment();
    await new KevClient(async () => ({ ...response(catalogue()), truncated: true }), () => NOW).enrich(a);
    assert.equal(a.threatIntelligence?.status, 'unavailable');
});

test('stale positive KEV matches remain visible while absent entries become unknown', async () => {
    let now = NOW, failed = false;
    const client = new KevClient(async () => { if (failed) throw new Error('offline'); return response(catalogue()); }, () => now);
    await client.enrich(assessment());
    now += 2 * 60 * 60_000; failed = true;
    const positive = assessment(), absent = assessment('CVE-2026-99999');
    await client.enrich(positive); await client.enrich(absent);
    assert.equal(positive.threatIntelligence?.status, 'stale');
    assert.equal(positive.findings[0].advisory?.knownExploited, true);
    assert.equal(absent.findings[0].advisory?.knownExploited, null);
    now += 8 * 86400_000;
    await client.enrich(positive);
    assert.equal(positive.threatIntelligence?.status, 'unavailable');
    assert.equal(positive.findings[0].advisory?.knownExploited, null);
});

test('grouping preserves each finding, separates surfaces and excludes another origin', () => {
    const base = assessment().findings[0];
    const findings = [base, { ...base, id: 'php', advisory: undefined, checkId: 'php-error' }, { ...base, id: 'db', advisory: undefined, checkId: 'database-error-unknown' }, { ...base, id: 'other-host', asset: 'https://another.example/' }];
    const before = JSON.stringify(findings);
    const groups = groupFindings('https://example.com', findings);
    assert.equal(groups.length, 3);
    assert.deepEqual(groups.flatMap(g => g.findingIds).sort(), ['db', 'fixture-finding', 'php']);
    assert.equal(JSON.stringify(findings), before);
    assert.ok(groups.every(g => /No exploit chain/.test(g.reason)));
});
