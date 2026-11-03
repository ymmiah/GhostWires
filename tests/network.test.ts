import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import dns from 'node:dns/promises';
import https from 'node:https';
import { gzipSync } from 'node:zlib';
import { isBlockedIP, normalizeTarget, assertPublicHost, pinnedLookup, safeFetch, TargetError } from '../server/net';
import { createOwnershipChallenge, verifyOwnership } from '../server/assessment/ownership';
import { withScanSlot } from '../server/assessment/slots';

const publicDNS = () => mock.method(dns, 'lookup', async () => [{ address: '93.184.215.14', family: 4 }]);

test('SSRF guard blocks reserved, mapped, expanded, NAT64 and transition addresses', () => {
    for (const ip of ['127.0.0.1', '0.0.0.0', '10.0.0.1', '169.254.169.254', '100.64.0.1', '192.168.1.1', '::1', '::', 'fc00::1', 'fe80::1', 'ff02::1', '::ffff:127.0.0.1', '0:0:0:0:0:ffff:7f00:1', '64:ff9b::7f00:1', '2002:7f00:1::', '2001::1', '2001:db8::1', '3fff::1']) assert.equal(isBlockedIP(ip), true, ip);
    for (const ip of ['93.184.215.14', '8.8.8.8', '2606:4700:4700::1111', '::ffff:808:808']) assert.equal(isBlockedIP(ip), false, ip);
});

test('URL objects cannot bypass protocol, credential or port validation', async () => {
    for (const url of ['ftp://example.com/', 'https://user:pass@example.com', 'http://localhost./', 'http://[::1]:9999/']) assert.throws(() => normalizeTarget(url));
    await assert.rejects(safeFetch(new URL('ftp://example.com/')), /Only http/);
    await assert.rejects(safeFetch(new URL('http://169.254.169.254/')), /Blocked/);
});

test('mixed public/private DNS answers fail closed', async () => {
    const lookup = mock.method(dns, 'lookup', async () => [{ address: '93.184.215.14', family: 4 }, { address: '127.0.0.1', family: 4 }]);
    try { await assert.rejects(assertPublicHost('example.com'), /private\/reserved/); } finally { lookup.mock.restore(); }
});

test('pinned socket lookup only supplies validated addresses and never performs a second DNS lookup', () => {
    const lookup = pinnedLookup(['93.184.215.14', '127.0.0.1']);
    lookup('attacker-controlled.invalid', { all: true }, (err, values) => { assert.equal(err, null); assert.deepEqual(values, [{ address: '93.184.215.14', family: 4 }]); });
    lookup('example.com', { family: 6 }, err => assert.ok(err instanceof TargetError));
});

function transport(responses: { status?: number; headers?: Record<string, string>; body?: Buffer | string; fail?: boolean }[]) {
    let calls = 0;
    const fn = mock.method(https, 'request', (_url: URL, options: any, callback: (res: any) => void) => {
        const req = new EventEmitter() as any;
        req.destroy = () => {};
        req.end = () => queueMicrotask(() => {
            if (options.signal.aborted) { req.emit('error', new Error('aborted')); return; }
            options.lookup('ignored-second-dns.example', { all: true }, (error: any, ips: any) => { assert.equal(error, null); assert.equal(ips[0].address, '93.184.215.14'); });
            const spec = responses[calls++] || {};
            const res = new PassThrough() as any;
            res.statusCode = spec.status || 200; res.headers = spec.headers || {};
            callback(res);
            if (spec.fail) res.destroy(new Error('body interrupted'));
            else res.end(spec.body || 'Hello');
        });
        return req;
    });
    return { restore: () => fn.mock.restore(), count: () => calls };
}

test('redirect to another origin is rejected before making that connection', async () => {
    const dnsMock = publicDNS(); const wire = transport([{ status: 302, headers: { location: 'https://other.example/.env' } }]);
    try {
        await assert.rejects(safeFetch('https://example.com/.env', { sameOrigin: 'https://example.com' }), /approved origin/);
        assert.equal(wire.count(), 1);
    } finally { wire.restore(); dnsMock.mock.restore(); }
});

test('redirects to private addresses are blocked and redirect budgets are enforced', async () => {
    const dnsMock = publicDNS(); let wire = transport([{ status: 302, headers: { location: 'http://127.0.0.1/' } }]);
    try { await assert.rejects(safeFetch('https://example.com/'), /Blocked/); assert.equal(wire.count(), 1); }
    finally { wire.restore(); }
    wire = transport([{ status: 302, headers: { location: '/another' } }]);
    try { await assert.rejects(safeFetch('https://example.com/', { maxRedirects: 0 }), /Too many redirects/); }
    finally { wire.restore(); dnsMock.mock.restore(); }
});

test('body limits apply after decompression and label truncation', async () => {
    const dnsMock = publicDNS(); const wire = transport([{ body: gzipSync('x'.repeat(10000)), headers: { 'content-encoding': 'gzip' } }]);
    try { const r = await safeFetch('https://example.com/', { maxBytes: 100 }); assert.equal(r.body.length, 100); assert.equal(r.truncated, true); }
    finally { wire.restore(); dnsMock.mock.restore(); }
});

test('interrupted responses are errors rather than silently complete evidence', async () => {
    const dnsMock = publicDNS(); const wire = transport([{ fail: true }]);
    try { await assert.rejects(safeFetch('https://example.com/'), /interrupted/); }
    finally { wire.restore(); dnsMock.mock.restore(); }
});

test('pre-cancelled requests do not connect', async () => {
    const controller = new AbortController(); controller.abort();
    await assert.rejects(safeFetch('https://example.com/', { signal: controller.signal }), /cancelled/);
});

test('owner proof requires signed, unexpired, exact-origin token and matching DNS TXT value', async () => {
    const dnsMock = publicDNS(); const now = Date.now();
    try {
        const c = await createOwnershipChallenge('https://example.com/', now);
        await verifyOwnership('https://example.com/path', c.token, now, async () => [[c.recordValue]]);
        await assert.rejects(verifyOwnership('https://other.example/', c.token, now, async () => [[c.recordValue]]), /different origin/);
        await assert.rejects(verifyOwnership('http://example.com/', c.token, now, async () => [[c.recordValue]]), /different origin/);
        await assert.rejects(verifyOwnership('https://example.com/', c.token, now + 31 * 60_000, async () => [[c.recordValue]]), /expired/);
        await assert.rejects(verifyOwnership('https://example.com/', c.token + 'x', now), /Invalid/);
        await assert.rejects(verifyOwnership('https://example.com/', c.token, now, async () => [['wrong record']] ), /not found/);
        await assert.rejects(verifyOwnership('https://example.com/', undefined, now), /proof/);
        await assert.rejects(createOwnershipChallenge('https://8.8.8.8/'), /domain/);
    } finally { dnsMock.mock.restore(); }
});

test('scan concurrency is bounded and released after failures', async () => {
    let release: () => void;
    const first = withScanSlot('https://one.example/', () => new Promise<void>(resolve => { release = resolve; }));
    await assert.rejects(withScanSlot('https://one.example/', async () => {}), /busy/);
    let releaseSecond: () => void;
    const second = withScanSlot('https://two.example/', () => new Promise<void>(resolve => { releaseSecond = resolve; }));
    await assert.rejects(withScanSlot('https://three.example/', async () => {}), /busy/);
    release!(); releaseSecond!(); await Promise.all([first, second]);
    await assert.rejects(withScanSlot('https://one.example/', async () => { throw new Error('fixture'); }), /fixture/);
    assert.equal(await withScanSlot('https://one.example/', async () => 42), 42);
});
