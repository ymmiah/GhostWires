import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { WorkspaceStore } from '../server/workspace/store';
import { workspaceRouter } from '../server/workspace/routes';
import { assessment } from './fixtures/assessment';

const password = 'HTTP-fixture-password-42!';
async function fixture(t: any, secure = false) {
    const store = new WorkspaceStore(':memory:');
    await store.createAccount('alpha', 'owner@example.com', password, 'owner');
    await store.createAccount('beta', 'other@example.com', password, 'owner');
    await store.createAccount('alpha', 'viewer@example.com', password, 'viewer');
    const app = express(); app.use(express.json()); app.use('/api/workspace', workspaceRouter(store, secure));
    const server = app.listen(0, '127.0.0.1');
    await new Promise<void>(resolve => server.once('listening', resolve));
    const base = `http://127.0.0.1:${(server.address() as any).port}/api/workspace`;
    t.after(async () => { await new Promise<void>(resolve => server.close(() => resolve())); store.close(); });
    const login = async (email = 'owner@example.com') => {
        const res = await fetch(`${base}/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, password }) });
        assert.equal(res.status, 200);
        const setCookie = res.headers.get('set-cookie')!;
        const cookie = setCookie.split(';')[0];
        const session = await res.json();
        return { cookie, session, setCookie, principal: store.session(cookie.split('=')[1])! };
    };
    const request = (route: string, auth: Awaited<ReturnType<typeof login>>, method = 'GET', body?: unknown, headers = {}) => fetch(`${base}${route}`, { method, headers: { cookie: auth.cookie, 'content-type': 'application/json', 'x-workspace-csrf': auth.session.csrfToken, ...headers }, ...(method === 'GET' ? {} : { body: JSON.stringify(body || {}) }) });
    return { store, base, login, request };
}

test('workspace API requires authentication and uses private secure session cookies', async t => {
    const { base, login, request } = await fixture(t, true);
    assert.equal((await fetch(`${base}/investigations`)).status, 401);
    const owner = await login();
    assert.match(owner.setCookie, /^__Host-gw_workspace=/);
    assert.match(owner.setCookie, /HttpOnly/); assert.match(owner.setCookie, /Secure/); assert.match(owner.setCookie, /SameSite=Strict/); assert.match(owner.setCookie, /Path=\//);
    const me = await request('/session', owner); assert.equal(me.headers.get('cache-control'), 'no-store');
    assert.equal((await me.json()).user.role, 'owner');
    await request('/logout', owner, 'POST');
    assert.equal((await request('/investigations', owner)).status, 401);
});

test('workspace API blocks cross-site login, non-JSON writes and missing CSRF', async t => {
    const { base, login, request } = await fixture(t);
    const crossSite = await fetch(`${base}/login`, { method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://evil.example' }, body: JSON.stringify({ email: 'owner@example.com', password }) });
    assert.equal(crossSite.status, 403);
    const form = await fetch(`${base}/login`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'email=x' });
    assert.equal(form.status, 415);
    const owner = await login();
    assert.equal((await request('/logout', owner, 'POST', {}, { 'x-workspace-csrf': '' })).status, 403);
    assert.equal((await request('/logout', owner, 'POST', {}, { 'sec-fetch-site': 'cross-site' })).status, 403);
    assert.equal((await request('/investigations', owner)).status, 200);
});

test('workspace API cannot save unsigned or edited evidence or select another tenant', async t => {
    const { store, login, request } = await fixture(t);
    const owner = await login(), other = await login('other@example.com'), a = assessment();
    assert.equal((await request('/investigations', owner, 'POST', { assessment: a, receipt: 'fake' })).status, 403);
    const receipt = store.receipt(a, owner.principal);
    const save = await request('/investigations', owner, 'POST', { assessment: a, receipt, tenantId: other.principal.tenantId, role: 'owner' });
    assert.equal(save.status, 201); const item = await save.json();
    assert.equal((await request('/investigations', other)).status, 200);
    assert.deepEqual((await (await request('/investigations', other)).json()).investigations, []);
    for (const [method, body] of [['GET', undefined], ['PATCH', { state: 'resolved', note: 'forged', version: 1 }], ['DELETE', {}]] as const) assert.equal((await request(`/investigations/${item.id}`, other, method, body)).status, 404);
    assert.equal((await request('/investigations', owner, 'POST', { assessment: { ...a, scope: 'https://changed.example' }, receipt })).status, 403);
});

test('viewer API access remains read-only even with forged role fields', async t => {
    const { store, login, request } = await fixture(t);
    const owner = await login(), viewer = await login('viewer@example.com'), a = assessment();
    const item = store.save(owner.principal, a, store.receipt(a, owner.principal));
    assert.equal((await request(`/investigations/${item.id}`, viewer)).status, 200);
    assert.equal((await request(`/investigations/${item.id}`, viewer, 'PATCH', { state: 'resolved', note: 'x', version: 1, role: 'owner' })).status, 403);
    assert.equal((await request(`/investigations/${item.id}`, viewer, 'DELETE', { role: 'owner' })).status, 403);
    assert.equal((await request('/investigations', viewer, 'POST', { assessment: a, receipt: store.receipt(a, owner.principal), role: 'owner' })).status, 403);
});
