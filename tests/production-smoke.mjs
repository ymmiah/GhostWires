// Run after npm run build. Uses only the built server and local HTTP requests.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';

const port = '3418';
const server = spawn(process.execPath, ['dist-server/server.cjs'], {
    env: { ...process.env, HOST: '127.0.0.1', PORT: port, GHOSTWIRES_BYOK_ONLY: '1' }, stdio: ['ignore', 'pipe', 'pipe'],
});
let log = '';
server.stdout.on('data', d => { log += d; });
server.stderr.on('data', d => { log += d; });
try {
    const base = `http://127.0.0.1:${port}`;
    let health;
    for (let i = 0; i < 50; i++) {
        try { health = await fetch(`${base}/api/health`); break; }
        catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    assert.ok(health, log);
    const data = await health.json();
    assert.equal(data.version, '4.1.0'); assert.equal(data.byokOnly, true);
    for (const [body, status] of [
        [{ url: 'http://169.254.169.254/' }, 403],
        [{ url: 'https://example.com/', mode: 'owner' }, 403],
        [{ url: 'https://example.com/', mode: 'bad' }, 400],
        [{ url: 'https://example.com/', inventory: [{ name: 'x/y', version: '1.0.0' }] }, 403],
        [{ url: 'https://example.com/', inventory: {} }, 400],
    ]) {
        const res = await fetch(`${base}/api/recon`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
        assert.equal(res.status, status, JSON.stringify(await res.json()));
        assert.equal(res.headers.get('cache-control'), 'no-store');
    }
    const proof = await fetch(`${base}/api/ownership/challenge`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: 'http://localhost/' }) });
    assert.equal(proof.status, 403);
    const ui = await fetch(base);
    assert.ok((await ui.text()).includes('GhostWires'));
    assert.ok(ui.headers.get('content-security-policy').includes("script-src 'self'"));
    console.log('Production smoke passed: health, static UI/CSP, owner enforcement, inventory validation, private target block, no-store.');
} finally { server.kill(); }
