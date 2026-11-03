import { DatabaseSync } from 'node:sqlite';
import { createHash, createHmac, randomBytes, randomUUID, scrypt, timingSafeEqual } from 'node:crypto';
import { mkdirSync, chmodSync } from 'node:fs';
import path from 'node:path';
import type { Investigation, InvestigationSummary, ReviewState, SurfaceAssessment, WorkspaceRole } from '../../types';
import { TargetError } from '../net';
import { redactEvidence } from '../assessment/redact';

// OWASP's 32 MiB scrypt profile; two concurrent verifications are the process maximum.
const derive = (password: string, salt: string) => new Promise<string>((resolve, reject) => {
    scrypt(password, salt, 64, { N: 32768, r: 8, p: 3, maxmem: 64 * 1024 * 1024 }, (error, key) => error ? reject(error) : resolve(`scrypt$32768$8$3$${key.toString('hex')}`));
});
const hash = (text: string) => createHash('sha256').update(text).digest('hex');
const equal = (a: string, b: string) => { const left = Buffer.from(a), right = Buffer.from(b); return left.length === right.length && timingSafeEqual(left, right); };
const STATES: ReviewState[] = ['open', 'in-review', 'resolved', 'accepted-risk'];
const ROLES: WorkspaceRole[] = ['owner', 'analyst', 'viewer'];
export interface Principal { userId: string; tenantId: string; email: string; role: WorkspaceRole; workspace: string; tokenHash: string; csrfToken: string; }

/** Canonical JSON is used only for bounded, JSON-shaped assessment data. */
export function canonical(value: unknown, depth = 0): string {
    if (depth > 20) throw new TargetError('Assessment nesting exceeds the supported limit.');
    if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
    if (Array.isArray(value)) return `[${value.map(v => canonical(v, depth + 1)).join(',')}]`;
    return `{${Object.keys(value).filter(k => value[k] !== undefined).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k], depth + 1)}`).join(',')}}`;
}

export class WorkspaceStore {
    private db: DatabaseSync;
    private key: string;
    private authInFlight = 0;
    constructor(filename: string, readonly retentionDays = 30, private clock = Date.now) {
        if (!Number.isInteger(retentionDays) || retentionDays < 1 || retentionDays > 90) throw new Error('Workspace retention must be between 1 and 90 days.');
        if (filename !== ':memory:') {
            const publicDirectory = path.join(process.cwd(), 'dist');
            if (!path.isAbsolute(filename) || path.resolve(filename) === publicDirectory || path.resolve(filename).startsWith(publicDirectory + path.sep)) throw new Error('Workspace database requires an absolute path outside the public dist directory.');
            mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
        }
        this.db = new DatabaseSync(filename);
        if (filename !== ':memory:') chmodSync(filename, 0o600);
        this.db.exec(`
            PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 3000; PRAGMA journal_mode = WAL; PRAGMA secure_delete = ON;
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE);
            CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), email TEXT NOT NULL UNIQUE, role TEXT NOT NULL CHECK(role IN ('owner','analyst','viewer')), salt TEXT NOT NULL, password_hash TEXT NOT NULL, failures INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS investigations (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), digest TEXT NOT NULL, scope TEXT NOT NULL, title TEXT NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, version INTEGER NOT NULL DEFAULT 1, finding_count INTEGER NOT NULL, kev_count INTEGER NOT NULL, assessment TEXT NOT NULL, UNIQUE(tenant_id,digest), UNIQUE(tenant_id,id));
            CREATE TABLE IF NOT EXISTS events (tenant_id TEXT NOT NULL, investigation_id TEXT NOT NULL, sequence INTEGER NOT NULL, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL, PRIMARY KEY(tenant_id,investigation_id,sequence), FOREIGN KEY(tenant_id,investigation_id) REFERENCES investigations(tenant_id,id) ON DELETE CASCADE);
            CREATE INDEX IF NOT EXISTS investigations_tenant ON investigations(tenant_id,created_at DESC);
            CREATE INDEX IF NOT EXISTS investigations_expiry ON investigations(expires_at);
        `);
        this.db.prepare('INSERT OR IGNORE INTO metadata(key,value) VALUES (?,?)').run('receipt-key', randomBytes(32).toString('hex'));
        this.key = String(this.db.prepare('SELECT value FROM metadata WHERE key=?').get('receipt-key')!.value);
        this.purge();
    }
    close() { this.db.close(); }
    purge() {
        const now = this.clock();
        this.db.prepare('DELETE FROM investigations WHERE expires_at<=?').run(now);
        this.db.prepare('DELETE FROM sessions WHERE expires_at<=?').run(now);
    }
    private transaction<T>(fn: () => T): T {
        this.db.exec('BEGIN IMMEDIATE');
        try { const value = fn(); this.db.exec('COMMIT'); return value; }
        catch (e) { this.db.exec('ROLLBACK'); throw e; }
    }
    private signature(text: string) { return createHmac('sha256', this.key).update(text).digest('hex'); }

    /** Provisioning is local-only. There is no public registration or role-changing API. */
    async createAccount(workspace: string, email: string, password: string, role: WorkspaceRole) {
        email = email.trim().toLowerCase();
        if (!/^[a-z0-9][a-z0-9-]{1,47}$/.test(workspace) || !/^[^\s@]{1,100}@[^\s@.]+(?:\.[^\s@.]+)+$/.test(email) || email.length > 200 || !ROLES.includes(role) || password.length < 14 || password.length > 256 || !password.trim()) throw new Error('Use a workspace slug (2–48 characters), valid email, supported role and a password of 14–256 characters.');
        const salt = randomBytes(16).toString('hex');
        const passwordHash = await derive(password, salt);
        this.transaction(() => {
            if (this.db.prepare('SELECT id FROM accounts WHERE email=?').get(email)) throw new Error('Account already exists. Revoke it explicitly before provisioning a replacement.');
            this.db.prepare('INSERT OR IGNORE INTO tenants(id,name) VALUES (?,?)').run(randomUUID(), workspace);
            const tenant = this.db.prepare('SELECT id FROM tenants WHERE name=?').get(workspace)!;
            this.db.prepare('INSERT INTO accounts(id,tenant_id,email,role,salt,password_hash) VALUES (?,?,?,?,?,?)').run(randomUUID(), String(tenant.id), email, role, salt, passwordHash);
        });
    }
    revokeAccount(email: string) {
        // Session revocation is immediate; old ledger entries keep the actor attribution.
        this.db.prepare('DELETE FROM accounts WHERE email=?').run(email.trim().toLowerCase());
    }
    async login(email: unknown, password: unknown): Promise<string> {
        if (typeof email !== 'string' || typeof password !== 'string' || email.length > 200 || password.length > 256) throw new TargetError('Email or password not recognised.', 401);
        if (this.authInFlight >= 2) throw new TargetError('Sign-in is busy; retry shortly.', 429);
        this.authInFlight++;
        try {
            const account = this.db.prepare('SELECT * FROM accounts WHERE email=?').get(email.trim().toLowerCase());
            const candidate = await derive(password, String(account?.salt || 'ghostwires-nonexistent-account'));
            if (!account || !equal(candidate, String(account.password_hash)) || Number(account.locked_until) > this.clock()) {
                if (account && Number(account.locked_until) <= this.clock()) this.db.prepare('UPDATE accounts SET failures=failures+1, locked_until=CASE WHEN failures>=4 THEN ? ELSE 0 END WHERE id=?').run(this.clock() + 15 * 60_000, String(account.id));
                throw new TargetError('Email or password not recognised, or sign-in temporarily locked.', 401);
            }
            const token = randomBytes(32).toString('base64url');
            this.transaction(() => {
                this.db.prepare('UPDATE accounts SET failures=0,locked_until=0 WHERE id=?').run(String(account.id));
                this.db.prepare('DELETE FROM sessions WHERE user_id=? AND token_hash NOT IN (SELECT token_hash FROM sessions WHERE user_id=? ORDER BY created_at DESC LIMIT 9)').run(String(account.id), String(account.id));
                this.db.prepare('INSERT INTO sessions VALUES (?,?,?,?)').run(hash(token), String(account.id), this.clock() + 8 * 60 * 60_000, this.clock());
            });
            return token;
        } finally { this.authInFlight--; }
    }
    session(token: string | undefined): Principal | null {
        if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
        const tokenHash = hash(token);
        const row = this.db.prepare('SELECT a.id,a.tenant_id,a.email,a.role,t.name FROM sessions s JOIN accounts a ON a.id=s.user_id JOIN tenants t ON t.id=a.tenant_id WHERE s.token_hash=? AND s.expires_at>?').get(tokenHash, this.clock());
        return row ? { userId: String(row.id), tenantId: String(row.tenant_id), email: String(row.email), role: row.role as WorkspaceRole, workspace: String(row.name), tokenHash, csrfToken: this.signature(`csrf:${token}`) } : null;
    }
    logout(p: Principal) { this.db.prepare('DELETE FROM sessions WHERE token_hash=?').run(p.tokenHash); }
    assertCsrf(p: Principal, value: unknown) { if (typeof value !== 'string' || !equal(value, p.csrfToken)) throw new TargetError('Refresh the workspace before making this change.', 403); }
    private assertWriter(p: Principal) { if (p.role === 'viewer') throw new TargetError('This account has read-only access.', 403); }
    receipt(a: SurfaceAssessment, p: Principal): string | undefined {
        if (a.mode !== 'owner' || p.role === 'viewer') return undefined;
        const expires = this.clock() + 15 * 60_000;
        const digest = hash(canonical(a));
        return `${expires}.${digest}.${this.signature(`assessment:${p.tenantId}:${p.userId}:${p.tokenHash}:${expires}:${digest}`)}`;
    }
    private verifyReceipt(a: SurfaceAssessment, receipt: unknown, p: Principal): string {
        if (!a || a.mode !== 'owner' || !Array.isArray(a.findings) || a.findings.length > 500 || typeof a.scope !== 'string' || typeof receipt !== 'string' || receipt.length > 200) throw new TargetError('Save a fresh DNS-verified owner assessment from this signed-in session.', 403);
        const content = canonical(a);
        if (Buffer.byteLength(content) > 512 * 1024) throw new TargetError('Assessment exceeds the workspace size limit.', 413);
        const [expires, digest, signature, extra] = receipt.split('.');
        const expiry = Number(expires);
        const expected = this.signature(`assessment:${p.tenantId}:${p.userId}:${p.tokenHash}:${expires}:${digest}`);
        if (extra || !Number.isFinite(expiry) || expiry <= this.clock() || expiry > this.clock() + 15 * 60_000 || !digest || !signature || !equal(hash(content), digest) || !equal(expected, signature)) throw new TargetError('Assessment proof expired, was edited, or belongs to another session. Run the owner assessment again.', 403);
        return digest;
    }
    private summary(row: any): InvestigationSummary & { version: number } {
        return { id: row.id, scope: row.scope, title: row.title, state: row.state, createdAt: new Date(row.created_at).toISOString(), updatedAt: new Date(row.updated_at).toISOString(), expiresAt: new Date(row.expires_at).toISOString(), findingCount: row.finding_count, kevCount: row.kev_count, version: row.version };
    }
    list(p: Principal): InvestigationSummary[] {
        this.purge();
        return this.db.prepare('SELECT id,scope,title,state,created_at,updated_at,expires_at,version,finding_count,kev_count FROM investigations WHERE tenant_id=? AND expires_at>? ORDER BY created_at DESC LIMIT 200').all(p.tenantId, this.clock()).map(row => this.summary(row));
    }
    get(p: Principal, id: string): Investigation & { version: number } {
        const row = this.db.prepare('SELECT * FROM investigations WHERE tenant_id=? AND id=? AND expires_at>?').get(p.tenantId, id, this.clock());
        if (!row) throw new TargetError('Investigation not found.', 404);
        const assessment = JSON.parse(String(row.assessment));
        if (!equal(hash(canonical(assessment)), String(row.digest))) throw new TargetError('Saved evidence failed its integrity check.', 500);
        const timeline = this.db.prepare('SELECT sequence,at,actor,action,detail FROM events WHERE tenant_id=? AND investigation_id=? ORDER BY sequence').all(p.tenantId, id).map((e: any) => ({ sequence: e.sequence, at: new Date(e.at).toISOString(), actor: e.actor, action: e.action, detail: e.detail }));
        return { ...this.summary(row), assessment, timeline };
    }
    save(p: Principal, a: SurfaceAssessment, receipt: unknown): Investigation {
        this.assertWriter(p); this.purge();
        const digest = this.verifyReceipt(a, receipt, p);
        return this.transaction(() => {
            const previous = this.db.prepare('SELECT id FROM investigations WHERE tenant_id=? AND digest=?').get(p.tenantId, digest);
            if (previous) return this.get(p, String(previous.id));
            if (Number(this.db.prepare('SELECT count(*) AS n FROM investigations WHERE tenant_id=?').get(p.tenantId)!.n) >= 200) throw new TargetError('Workspace is full (200 investigations). Delete an old investigation or wait for retention expiry.', 409);
            const id = randomUUID(), now = this.clock();
            const title = `Assessment — ${new URL(a.scope).host}`;
            this.db.prepare('INSERT INTO investigations(id,tenant_id,digest,scope,title,state,created_at,updated_at,expires_at,finding_count,kev_count,assessment) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)').run(id, p.tenantId, digest, a.scope, title, 'open', now, now, now + this.retentionDays * 86400_000, a.findings.length, a.findings.filter(f => f.advisory?.knownExploited === true).length, JSON.stringify(a));
            this.db.prepare('INSERT INTO events VALUES (?,?,?,?,?,?,?)').run(p.tenantId, id, 1, now, p.email, 'saved', 'DNS-verified owner assessment saved. Evidence is a snapshot; no compromise is asserted.');
            return this.get(p, id);
        });
    }
    review(p: Principal, id: string, state: unknown, note: unknown, expectedVersion: unknown): Investigation {
        this.assertWriter(p);
        if (!STATES.includes(state as ReviewState) || typeof note !== 'string' || note.length > 2000 || !Number.isInteger(expectedVersion)) throw new TargetError('Choose a review state and a note of at most 2,000 characters.');
        const clean = redactEvidence(note.trim());
        return this.transaction(() => {
            const item = this.get(p, id);
            if (item.version !== expectedVersion) throw new TargetError('This investigation changed. Reload it before saving your review.', 409);
            if (state === item.state && !clean) throw new TargetError('Add a note or choose a different review state.');
            if (state !== item.state && ['resolved', 'accepted-risk'].includes(String(state)) && !clean) throw new TargetError('Add a reason when resolving or accepting risk.');
            const additions = Number(state !== item.state) + Number(!!clean);
            if (item.timeline.length + additions > 200) throw new TargetError('Investigation timeline reached its 200-entry limit.', 409);
            let sequence = item.timeline.length;
            const append = (action: string, detail: string) => this.db.prepare('INSERT INTO events VALUES (?,?,?,?,?,?,?)').run(p.tenantId, id, ++sequence, this.clock(), p.email, action, detail);
            if (state !== item.state) append('reviewed', `Review state: ${item.state} → ${state}. This is a human decision; remediation is not independently verified.`);
            if (clean) append('note', clean);
            this.db.prepare('UPDATE investigations SET state=?,updated_at=?,version=version+1 WHERE tenant_id=? AND id=?').run(String(state), this.clock(), p.tenantId, id);
            return this.get(p, id);
        });
    }
    delete(p: Principal, id: string) {
        if (p.role !== 'owner') throw new TargetError('Only workspace owners can delete investigations.', 403);
        this.get(p, id);
        this.db.prepare('DELETE FROM investigations WHERE tenant_id=? AND id=?').run(p.tenantId, id);
    }
}
