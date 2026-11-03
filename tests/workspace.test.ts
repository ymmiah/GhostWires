import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { WorkspaceStore, canonical } from '../server/workspace/store';
import { assessment } from './fixtures/assessment';

const password = 'Test-only-long-password-42!';
async function account(s: WorkspaceStore, workspace = 'alpha', email = 'owner@example.com', role: 'owner' | 'analyst' | 'viewer' = 'owner') {
    await s.createAccount(workspace, email, password, role);
    return s.session(await s.login(email, password))!;
}

test('saved evidence is immutable, idempotent, scoped and accompanied by a server-authored timeline', async () => {
    const s = new WorkspaceStore(':memory:');
    try {
        const p = await account(s), a = assessment();
        const item = s.save(p, a, s.receipt(a, p));
        assert.equal(item.state, 'open'); assert.equal(item.timeline.length, 1); assert.equal(item.timeline[0].actor, p.email);
        assert.equal(s.save(p, a, s.receipt(a, p)).id, item.id);
        assert.deepEqual(s.get(p, item.id).assessment, a);
        const reviewed = s.review(p, item.id, 'resolved', 'Owner manually verified the fix.', item.version);
        assert.equal(reviewed.state, 'resolved'); assert.equal(reviewed.timeline.length, 3);
        assert.deepEqual(reviewed.assessment, a);
        assert.match(reviewed.timeline[1].detail, /not independently verified/);
    } finally { s.close(); }
});

test('another tenant cannot list, read, update or delete an investigation', async () => {
    const s = new WorkspaceStore(':memory:');
    try {
        const alice = await account(s), bob = await account(s, 'beta', 'bob@example.com');
        const a = assessment(), item = s.save(alice, a, s.receipt(a, alice));
        assert.equal(s.list(bob).length, 0);
        for (const action of [() => s.get(bob, item.id), () => s.review(bob, item.id, 'resolved', 'Forged', 1), () => s.delete(bob, item.id), () => s.save(bob, a, s.receipt(a, alice))]) assert.throws(action);
        assert.equal(s.get(alice, item.id).state, 'open');
    } finally { s.close(); }
});

test('viewer is read-only; analyst may review but only owner may delete', async () => {
    const s = new WorkspaceStore(':memory:');
    try {
        const owner = await account(s), viewer = await account(s, 'alpha', 'viewer@example.com', 'viewer'), analyst = await account(s, 'alpha', 'analyst@example.com', 'analyst');
        const a = assessment(), item = s.save(owner, a, s.receipt(a, owner));
        assert.equal(s.get(viewer, item.id).id, item.id);
        assert.equal(s.receipt(a, viewer), undefined);
        assert.throws(() => s.save(viewer, a, s.receipt(a, owner)), /read-only/);
        assert.throws(() => s.review(viewer, item.id, 'in-review', '', 1), /read-only/);
        assert.throws(() => s.delete(analyst, item.id), /Only workspace owners/);
        assert.equal(s.review(analyst, item.id, 'in-review', '', 1).state, 'in-review');
        s.delete(owner, item.id); assert.throws(() => s.get(owner, item.id), /not found/);
    } finally { s.close(); }
});

test('receipts reject public, edited, expired, missing and different-session assessments', async () => {
    let now = Date.now(); const s = new WorkspaceStore(':memory:', 30, () => now);
    try {
        const p = await account(s), a = assessment(), proof = s.receipt(a, p);
        const nextSession = s.session(await s.login(p.email, password))!;
        assert.throws(() => s.save(nextSession, a, proof), /another session/);
        assert.throws(() => s.save(p, { ...a, scope: 'https://another.example' }, proof), /edited/);
        assert.throws(() => s.save(p, a, undefined), /fresh/);
        assert.equal(s.receipt({ ...a, mode: 'public' }, p), undefined);
        assert.throws(() => s.save(p, { ...a, mode: 'public' }, proof), /fresh/);
        now += 16 * 60_000;
        assert.throws(() => s.save(p, a, proof), /expired/);
    } finally { s.close(); }
});

test('review requires reasons for closure and prevents lost updates; notes are redacted', async () => {
    const s = new WorkspaceStore(':memory:');
    try {
        const p = await account(s), a = assessment(), item = s.save(p, a, s.receipt(a, p));
        assert.throws(() => s.review(p, item.id, 'accepted-risk', '', 1), /reason/);
        assert.throws(() => s.review(p, item.id, 'arbitrary', '', 1), /Choose/);
        const next = s.review(p, item.id, 'in-review', 'DB_PASSWORD=private-value', 1);
        assert.ok(!JSON.stringify(next).includes('private-value'));
        assert.throws(() => s.review(p, item.id, 'resolved', 'stale update', 1), /changed/);
        assert.equal(s.get(p, item.id).version, 2);
    } finally { s.close(); }
});

test('retention removes expired evidence and timelines; sessions expire and revoke immediately', async () => {
    let now = Date.now(); const s = new WorkspaceStore(':memory:', 1, () => now);
    try {
        await s.createAccount('alpha', 'owner@example.com', password, 'owner');
        const token = await s.login('owner@example.com', password), p = s.session(token)!;
        const a = assessment(), item = s.save(p, a, s.receipt(a, p));
        now += 9 * 60 * 60_000; assert.equal(s.session(token), null);
        now += 16 * 60 * 60_000; s.purge();
        const next = s.session(await s.login('owner@example.com', password))!;
        assert.equal(s.list(next).length, 0); assert.throws(() => s.get(next, item.id), /not found/);
        const logoutToken = await s.login('owner@example.com', password); s.logout(s.session(logoutToken)!); assert.equal(s.session(logoutToken), null);
        const revokeToken = await s.login('owner@example.com', password); s.revokeAccount('owner@example.com'); assert.equal(s.session(revokeToken), null);
    } finally { s.close(); }
});

test('password hashing, lockouts and byte-safe CSRF comparisons reject invalid credentials', async () => {
    let now = Date.now(); const s = new WorkspaceStore(':memory:', 30, () => now);
    try {
        const p = await account(s);
        s.assertCsrf(p, p.csrfToken);
        assert.throws(() => s.assertCsrf(p, 'é'.repeat(64)), /Refresh/);
        assert.throws(() => s.assertCsrf(p, undefined), /Refresh/);
        for (let i = 0; i < 5; i++) await assert.rejects(s.login(p.email, 'wrong'), /not recognised/);
        await assert.rejects(s.login(p.email, password), /locked/);
        now += 16 * 60_000; assert.ok(s.session(await s.login(p.email, password)));
        await assert.rejects(s.login('unknown@example.com', password), /not recognised/);
    } finally { s.close(); }
});

test('file-backed workspaces persist across restarts without plaintext passwords or session tokens', async () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'ghostwires-workspace-')), filename = path.join(directory, 'workspace.sqlite');
    let s = new WorkspaceStore(filename);
    try {
        const p = await account(s), a = assessment();
        const token = await s.login(p.email, password), receipt = s.receipt(a, s.session(token)!);
        const item = s.save(s.session(token)!, a, receipt);
        assert.equal(statSync(filename).mode & 0o777, 0o600);
        s.close(); s = new WorkspaceStore(filename);
        assert.equal(s.get(s.session(token)!, item.id).findingCount, 1);
        assert.equal(s.save(s.session(token)!, a, receipt).id, item.id);
        const bytes = readFileSync(filename).toString('utf8');
        assert.ok(!bytes.includes(password)); assert.ok(!bytes.includes(token));
        const db = new DatabaseSync(filename);
        db.prepare('UPDATE investigations SET assessment=? WHERE id=?').run(JSON.stringify({ ...a, scope: 'https://tampered.example' }), item.id); db.close();
        assert.throws(() => s.get(s.session(token)!, item.id), /integrity/);
    } finally { s.close(); rmSync(directory, { recursive: true, force: true }); }
});

test('canonical evidence is independent of object key order and bounds nesting', () => {
    assert.equal(canonical({ b: 2, a: [1, 2] }), canonical({ a: [1, 2], b: 2 }));
    let nested: unknown = 'leaf'; for (let i = 0; i < 25; i++) nested = [nested];
    assert.throws(() => canonical(nested), /nesting/);
});
