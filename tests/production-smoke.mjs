// Run after npm run build. Uses only the built server and local HTTP requests.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const port = '3418';
const server = spawn(process.execPath, ['dist-server/server.cjs'], {
    env: { ...process.env, HOST: '127.0.0.1', PORT: port, GHOSTWIRES_BYOK_ONLY: '1', GHOSTWIRES_WORKSPACE_DB: '' }, stdio: ['ignore', 'pipe', 'pipe'],
});
let log = '';
let workspaceServer;
const directory = mkdtempSync(path.join(tmpdir(), 'ghostwires-production-'));
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
    assert.equal(data.version, JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version); assert.equal(data.byokOnly, true);
    const workspace = await fetch(`${base}/api/workspace/session`);
    assert.equal((await workspace.json()).enabled, false);
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
    const env = { ...process.env, GHOSTWIRES_WORKSPACE_DB: path.join(directory, 'workspace.sqlite'), GHOSTWIRES_RETENTION_DAYS: '30', NODE_ENV: 'production', HOST: '127.0.0.1', PORT: '3419', GHOSTWIRES_BYOK_ONLY: '1' };
    const password = 'Compiled-smoke-fixture-password!';
    const provision = spawnSync(process.execPath, ['dist-server/scripts/workspace-account.cjs', '--workspace', 'alpha', '--email', 'owner@example.com', '--role', 'owner', '--password-stdin'], { env, input: password, encoding: 'utf8' });
    assert.equal(provision.status, 0, provision.stderr);
    assert.ok(!provision.stdout.includes(password));
    workspaceServer = spawn(process.execPath, ['dist-server/server.cjs'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    workspaceServer.stdout.on('data', d => { log += d; }); workspaceServer.stderr.on('data', d => { log += d; });
    const workspaceBase = 'http://127.0.0.1:3419/api/workspace';
    let available;
    for (let i = 0; i < 50; i++) { try { available = await fetch(`${workspaceBase}/session`); break; } catch { await new Promise(r => setTimeout(r, 100)); } }
    assert.ok(available, log); assert.equal((await available.json()).enabled, true);
    const signedIn = await fetch(`${workspaceBase}/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'owner@example.com', password }) });
    assert.equal(signedIn.status, 200);
    assert.match(signedIn.headers.get('set-cookie'), /^__Host-gw_workspace=.*HttpOnly.*Secure.*SameSite=Strict/);
    const session = await signedIn.json(), cookie = signedIn.headers.get('set-cookie').split(';')[0];
    const headers = { 'content-type': 'application/json', cookie, 'x-workspace-csrf': session.csrfToken };
    const list = await fetch(`${workspaceBase}/investigations`, { headers }); assert.equal(list.status, 200); assert.deepEqual((await list.json()).investigations, []);
    const fake = await fetch(`${workspaceBase}/investigations`, { method: 'POST', headers, body: JSON.stringify({ assessment: { mode: 'owner', findings: [], scope: 'https://example.com' }, receipt: 'fake' }) });
    assert.equal(fake.status, 403);
    await fetch(`${workspaceBase}/logout`, { method: 'POST', headers, body: '{}' });
    assert.equal((await fetch(`${workspaceBase}/investigations`, { headers })).status, 401);
    console.log('Production smoke passed: health, UI/CSP, owner enforcement, inventory validation, SSRF, disabled/enabled workspace, compiled account provisioning, secure cookies, sign-in/out and forged-evidence rejection.');
} finally {
    for (const child of [server, workspaceServer].filter(Boolean)) { child.kill(); await new Promise(resolve => child.once('close', resolve)); }
    rmSync(directory, { recursive: true, force: true });
}
