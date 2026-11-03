import express, { type Request, type Response } from 'express';
import { WorkspaceStore, type Principal } from './store';
import { TargetError } from '../net';
import { rateLimit } from '../rateLimit';

export function sessionFromRequest(store: WorkspaceStore | null, req: Request, secure: boolean): Principal | null {
    const name = secure ? '__Host-gw_workspace' : 'gw_workspace';
    const cookie = req.headers.cookie?.split(';').map(v => v.trim()).find(v => v.startsWith(`${name}=`));
    return store?.session(cookie?.slice(name.length + 1)) || null;
}

export function workspaceRouter(store: WorkspaceStore | null, secure: boolean) {
    const router = express.Router();
    const name = secure ? '__Host-gw_workspace' : 'gw_workspace';
    const cookie = { httpOnly: true, secure, sameSite: 'strict' as const, path: '/', maxAge: 8 * 60 * 60_000 };
    router.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); res.setHeader('Pragma', 'no-cache'); next(); });
    router.use(rateLimit('workspace requests', 120, 60_000));
    router.get('/session', (req, res) => {
        const p = sessionFromRequest(store, req, secure);
        res.json({ enabled: !!store, ...(p ? { user: { email: p.email, role: p.role, workspace: p.workspace }, csrfToken: p.csrfToken } : {}), ...(store ? { retentionDays: store.retentionDays } : {}) });
    });
    router.use((req, res, next) => {
        if (!store) return res.status(503).json({ error: 'Saved workspaces are not enabled on this deployment.' });
        if (req.method !== 'GET') {
            if (!req.is('application/json')) return res.status(415).json({ error: 'JSON requests are required.' });
            const origin = req.get('origin');
            if (req.get('sec-fetch-site') === 'cross-site' || (origin && origin !== `${req.protocol}://${req.get('host')}`)) return res.status(403).json({ error: 'Cross-site workspace changes are blocked.' });
        }
        next();
    });
    router.post('/login', rateLimit('workspace sign-in', 5, 60_000), async (req, res) => {
        try {
            const token = await store!.login(req.body?.email, req.body?.password);
            res.cookie(name, token, cookie);
            const p = store!.session(token)!;
            res.json({ enabled: true, user: { email: p.email, role: p.role, workspace: p.workspace }, csrfToken: p.csrfToken, retentionDays: store!.retentionDays });
        } catch (e) { fail(res, e); }
    });
    router.use((req, res, next) => {
        const p = sessionFromRequest(store, req, secure);
        if (!p) return res.status(401).json({ error: 'Sign in to your workspace.' });
        try {
            if (req.method !== 'GET') store!.assertCsrf(p, req.get('x-workspace-csrf'));
            res.locals.principal = p;
            next();
        } catch (e) { fail(res, e); }
    });
    router.post('/logout', (_req, res) => { store!.logout(res.locals.principal); res.clearCookie(name, cookie); res.json({ ok: true }); });
    router.get('/investigations', (_req, res) => {
        try { res.json({ investigations: store!.list(res.locals.principal) }); } catch (e) { fail(res, e); }
    });
    router.post('/investigations', rateLimit('workspace save', 10, 60_000), (req, res) => {
        try { res.status(201).json(store!.save(res.locals.principal, req.body?.assessment, req.body?.receipt)); } catch (e) { fail(res, e); }
    });
    router.use('/investigations/:id', (req, res, next) => {
        if (!/^[a-f0-9-]{36}$/.test(String(req.params.id))) return res.status(404).json({ error: 'Investigation not found.' });
        next();
    });
    router.get('/investigations/:id', (req, res) => {
        try { res.json(store!.get(res.locals.principal, String(req.params.id))); } catch (e) { fail(res, e); }
    });
    router.patch('/investigations/:id', rateLimit('workspace review', 30, 60_000), (req, res) => {
        try { res.json(store!.review(res.locals.principal, String(req.params.id), req.body?.state, req.body?.note, req.body?.version)); } catch (e) { fail(res, e); }
    });
    router.delete('/investigations/:id', (req, res) => {
        try { store!.delete(res.locals.principal, String(req.params.id)); res.json({ ok: true }); } catch (e) { fail(res, e); }
    });
    return router;
}

function fail(res: Response, e: unknown) {
    const status = e instanceof TargetError ? e.status : 500;
    if (status >= 500) console.error('[GhostWires] Workspace operation failed.');
    res.status(status).json({ error: status >= 500 ? 'Workspace operation failed. Check deployment storage and retry.' : (e as Error).message });
}
