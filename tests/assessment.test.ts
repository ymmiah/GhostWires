import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectExposures } from '../server/assessment/detect';
import { assessSurface, OWNER_PATHS } from '../server/assessment';
import { redactEvidence, redactReport } from '../server/assessment/redact';
import { assessAdvisories, matchesRange, validateInventory } from '../server/assessment/advisories';
import { validatedGuidance } from '../server/ai/intel';
import type { SafeResponse } from '../server/net';
import type { ReconReport } from '../types';

const NOW = '2026-11-03T12:00:00Z';
const robots = { found: true, disallow: [], allow: [], sitemaps: [] };
const page = (text: string, overrides: Partial<SafeResponse> = {}): SafeResponse => ({ url: 'https://example.com/', status: 200, headers: new Headers({ 'content-type': 'text/html' }), setCookies: [], body: Buffer.from(text), text, redirectChain: [], resolvedIPs: ['93.184.215.14'], timeMs: 10, ...overrides });

test('a clean PHP page produces only a version observation, not an invented CVE', () => {
    const r = detectExposures(page('<h1>Hello</h1>', { headers: new Headers({ 'content-type': 'text/html', 'x-powered-by': 'PHP/8.4.12' }) }), NOW);
    assert.deepEqual(r.findings.map(f => f.checkId), ['php-version']);
    assert.equal(r.findings[0].severity, 'info');
    assert.equal(r.coverage.find(c => c.checkId === 'php-lifecycle')?.status, 'completed');
});

test('unsupported PHP is a potential risk with vendor-backport and banner caveats', () => {
    const r = detectExposures(page('', { headers: new Headers({ 'x-powered-by': 'PHP/7.4.33' }) }), NOW);
    const f = r.findings.find(f => f.checkId === 'php-eol')!;
    assert.equal(f.status, 'potential-vulnerability');
    assert.ok(f.limitations.some(l => /backport/i.test(l)));
});

test('unknown branches and stale lifecycle snapshots do not claim current support', () => {
    for (const [version, now] of [['9.0.0', NOW], ['8.1.33', '2027-11-03T00:00:00Z']]) {
        const r = detectExposures(page('', { headers: new Headers({ 'x-powered-by': `PHP/${version}` }) }), now);
        assert.equal(r.coverage.find(c => c.checkId === 'php-lifecycle')?.status, 'partial');
        assert.ok(!r.findings.some(f => f.checkId === 'php-eol'));
    }
});

test('database errors identify a signature without proving injection or retaining credentials', () => {
    const r = detectExposures(page('<pre>SQLSTATE[HY000] [1045] DB_PASSWORD=hunter2 mysql://admin:secret@db.internal</pre>', { status: 500 }), NOW);
    const f = r.findings.find(f => f.checkId === 'database-error-mysql')!;
    assert.equal(f.status, 'observed-exposure');
    assert.ok(f.limitations.some(l => /does not prove SQL injection/.test(l)));
    assert.ok(!JSON.stringify(r).includes('hunter2'));
    assert.ok(!JSON.stringify(r).includes('admin:secret'));
});

test('database signatures cover distinct SQL and document/cache engines', () => {
    const cases = [ ['PostgreSQL', 'org.postgresql.util.PSQLException: failure'], ['SQL Server', 'Microsoft SQL Native Client'], ['Oracle', 'ORA-00933: error'], ['SQLite', 'SQLite3Exception'], ['MongoDB', 'MongoServerError: failure'], ['Redis', 'NOAUTH Authentication required'], ['Elasticsearch', '{"type":"security_exception"}'] ];
    for (const [name, text] of cases) assert.ok(detectExposures(page(text), NOW).components.some(c => c.name === name), name);
});

test('generic SQLSTATE errors do not invent a database engine', () => {
    const r = detectExposures(page('SQLSTATE[HY000]: driver error'), NOW);
    assert.equal(r.components.length, 0);
    assert.equal(r.findings[0].checkId, 'database-error-unknown');
    const sqlite = detectExposures(page('SQLSTATE[HY000] no such table'), NOW);
    assert.deepEqual(sqlite.components.map(c => c.name), ['SQLite']);
});

test('script and code examples do not become public database-error findings', () => {
    const r = detectExposures(page('<script>const example="MongoServerError:"</script><code>ORA-00933:</code><h1>Documentation</h1>'), NOW);
    assert.equal(r.findings.length, 0);
});

test('PHP diagnostics require corroborating markers', () => {
    assert.ok(!detectExposures(page('<p>Fatal error: something happened</p>'), NOW).findings.some(f => f.checkId === 'php-error'));
    assert.ok(detectExposures(page('<b>Fatal error</b>: Uncaught Error in /srv/app.php on line 4'), NOW).findings.some(f => f.checkId === 'php-error'));
    assert.ok(detectExposures(page('<h1>PHP Version 8.4.12</h1><p>Configuration File (php.ini) Path</p>'), NOW).findings.some(f => f.checkId === 'phpinfo'));
});

test('environment files require multiple key names; raw values are omitted', () => {
    assert.equal(detectExposures(page('DB_HOST=localhost'), NOW).findings.length, 0);
    const r = detectExposures(page('APP_ENV=production\nDB_PASSWORD=supersecret\nDB_HOST=localhost'), NOW);
    assert.ok(r.findings.some(f => f.checkId === 'environment-file'));
    assert.ok(!JSON.stringify(r).includes('supersecret'));
});

test('reachable database admin login is low-severity exposure, not unauthorised access', () => {
    const f = detectExposures(page('<title>phpMyAdmin</title><form>Log in</form>'), NOW).findings[0];
    assert.equal(f.severity, 'low');
    assert.ok(f.limitations.some(l => /does not establish/.test(l)));
});

test('truncated responses are explicitly partial', () => {
    const r = detectExposures(page('Hello', { truncated: true }), NOW);
    assert.equal(r.coverage.find(c => c.checkId === 'response-exposure')?.status, 'partial');
});

test('public mode never requests owner paths or advisory APIs without inventory', async () => {
    let requests = 0;
    const r = await assessSurface(page('Hello'), [], 'public', robots, [], undefined, async () => { requests++; throw new Error('Unexpected fetch'); });
    assert.equal(requests, 0);
    assert.equal(r.intelligence.status, 'not-requested');
    assert.ok(r.coverage.some(c => c.checkId === 'owner-paths' && c.status === 'not-assessed'));
});

test('owner checks are bounded and soft 404/SPA fallbacks do not create findings', async () => {
    const urls: string[] = [];
    const r = await assessSurface(page('Hello'), [], 'owner', robots, [], undefined, async (target, options) => {
        urls.push(String(target));
        assert.equal(options?.sameOrigin, 'https://example.com');
        assert.equal(options?.maxBytes, 32 * 1024);
        return page('<title>Application</title><p>Welcome</p>', { url: String(target) });
    });
    assert.equal(urls.length, OWNER_PATHS.length);
    assert.ok(urls.every(url => new URL(url).origin === 'https://example.com'));
    assert.equal(r.findings.length, 0);
});

test('unavailable robots policy prevents all owner-only requests', async () => {
    const r = await assessSurface(page('Hello'), [], 'owner', { ...robots, error: 'timeout' }, [], undefined, async () => { throw new Error('Must not fetch'); });
    assert.equal(r.coverage.filter(c => c.checkId.startsWith('owner-') && c.status === 'blocked').length, 5);
});

test('robots restrictions, access blocks and failures remain distinct coverage states', async () => {
    const r = await assessSurface(page('Hello'), [], 'owner', { ...robots, disallow: ['/.env', '/.git/', '/phpinfo.php'] }, [], undefined, async target => {
        if (String(target).includes('adminer')) throw new Error('timeout');
        return page('', { url: String(target), status: 403 });
    });
    assert.equal(r.coverage.filter(c => c.checkId.startsWith('owner-') && c.status === 'blocked').length, 4);
    assert.equal(r.coverage.filter(c => c.checkId.startsWith('owner-') && c.status === 'error').length, 1);
});

test('credential redaction covers nested evidence, DSNs, cookie headers and query strings', () => {
    const value = { raw: { 'set-cookie': 'PHPSESSID=secret; HttpOnly' }, sample: 'DB_PASSWORD="secret phrase"\nAPP_KEY=base64:secret\nPOSTGRES_PASSWORD=secret\nELASTIC_PASSWORD=secret\npostgresql://user:password@db/', url: 'https://example.com/?token=secret', nested: ['API_KEY=abcdef'] };
    const out = JSON.stringify(redactReport(value));
    assert.ok(!out.includes('secret'));
    assert.ok(!out.includes('abcdef'));
    assert.match(out, /REDACTED/);
    assert.equal(redactEvidence('normal text'), 'normal text');
});

test('inventory rejects branch versions, oversized or conflicting packages', () => {
    assert.deepEqual(validateInventory([{ name: 'laravel/framework', version: 'v8.0.0' }]), [{ name: 'laravel/framework', version: '8.0.0' }]);
    for (const input of [{}, [{ name: 'laravel/framework', version: 'dev-main' }], [{ name: 'x/y', version: '1.0.0' }, { name: 'x/y', version: '2.0.0' }], Array(101).fill({ name: 'x/y', version: '1.0.0' })]) assert.throws(() => validateInventory(input));
});

test('version-range matching checks boundaries and never guesses unsupported syntax', () => {
    assert.equal(matchesRange('8.0.1', '>= 8.0.0, < 8.0.2'), true);
    assert.equal(matchesRange('8.0.2', '>= 8.0.0, < 8.0.2'), false);
    assert.equal(matchesRange('8.0.0', '< 7.0.0 || >= 8.0.0, <= 8.1.0'), true);
    assert.equal(matchesRange('8.0.0', '^8.0.0'), null);
    assert.equal(matchesRange('8.0.0-rc1', '>= 8.0.0'), null);
});

test('advisory findings require exact product and version match; withdrawn/unreviewed records are excluded', async () => {
    const row = { ghsa_id: 'GHSA-aaaa-bbbb-cccc', cve_id: 'CVE-2026-12345', summary: 'Fixture advisory', severity: 'high', type: 'reviewed', vulnerabilities: [{ package: { ecosystem: 'composer', name: 'fixture/package' }, vulnerable_version_range: '>= 1.0.0, < 1.0.2', first_patched_version: '1.0.2' }] };
    const r = await assessAdvisories([{ name: 'fixture/package', version: '1.0.1' }], 'https://example.com/', NOW, async url => {
        assert.equal(new URL(String(url)).hostname, 'api.github.com');
        assert.ok(!String(url).includes('example.com'));
        return page(JSON.stringify([row, { ...row, ghsa_id: 'GHSA-dddd-eeee-ffff', withdrawn_at: NOW }, { ...row, type: 'unreviewed' }, { ...row, vulnerabilities: [{ ...row.vulnerabilities[0], package: { ecosystem: 'composer', name: 'other/package' } }] }]), { headers: new Headers() });
    });
    assert.equal(r.findings.length, 1);
    assert.equal(r.findings[0].status, 'potential-vulnerability');
    assert.equal(r.findings[0].advisory?.knownExploited, null);
    assert.equal(r.intelligence.status, 'current');
});

test('advisory rate limits become unavailable coverage, not a clean assessment', async () => {
    const r = await assessAdvisories([{ name: 'fixture/unavailable', version: '1.0.0' }], 'https://example.com/', NOW, async () => page('', { status: 429 }));
    assert.equal(r.coverage.status, 'error');
    assert.equal(r.intelligence.status, 'unavailable');
    assert.equal(r.findings.length, 0);
});

test('advisory pagination and unknown range syntax are labelled partial', async () => {
    const r = await assessAdvisories([{ name: 'fixture/partial', version: '1.0.0' }], 'https://example.com/', NOW, async () => page(JSON.stringify([{ ghsa_id: 'GHSA-aaaa-bbbb-eeee', type: 'reviewed', vulnerabilities: [{ package: { ecosystem: 'composer', name: 'fixture/partial' }, vulnerable_version_range: '^1.0' }] }]), { headers: new Headers({ link: '<https://api.github.com/advisories?after=x>; rel="next"' }) }));
    assert.equal(r.coverage.status, 'partial');
    assert.equal(r.findings.length, 0);
});

test('AI guidance rejects fabricated IDs and duplicate entries', () => {
    const r = { assessment: { findings: [{ id: 'known-finding' }] } } as ReconReport;
    const result = validatedGuidance([{ findingId: 'invented', explanation: 'x', recommendation: 'y' }, { findingId: 'known-finding', explanation: 'DB_PASSWORD=secret', recommendation: 'Rotate it' }, { findingId: 'known-finding', explanation: 'duplicate', recommendation: 'duplicate' }], r);
    assert.equal(result.length, 1);
    assert.ok(!result[0].explanation.includes('secret'));
});
