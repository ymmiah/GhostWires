// GhostWires Mk.IV — Express API + Vite dev middleware
// Author: Yasin Mohammed Miah, Student of BCU, BSc Computing Top-Up (Hons)
import './server/env';
import path from 'node:path';
import express, { type Request, type Response } from 'express';
import { runRecon, runCrawl, ENGINE, VERSION } from './server/recon';
import { safeFetch, TargetError } from './server/net';
import { rateLimit } from './server/rateLimit';
import { listProviders, redact, byokOnly, getProvider } from './server/ai/providers';
import { analyzeReport, describeImages, streamDebrief } from './server/ai/intel';

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';

function sendError(res: Response, err: any, secret?: string | null) {
    const status = err instanceof TargetError ? err.status : (err?.status || 500);
    const message = redact(err?.message || 'Internal error', secret);
    if (status >= 500) console.error('[GhostWires]', message); // never the raw error object (may hold request config)
    if (!res.headersSent) res.status(status).json({ error: message });
}

/**
 * BYOK: read the visitor's key from the request header for THIS request only.
 * It is never logged, persisted, echoed in responses, or stored in process.env.
 */
const KEY_HEADER = 'x-ghostwires-api-key';
const PROVIDER_HEADER = 'x-ghostwires-provider';
function byok(req: Request): { key: string | null; provider: string | undefined } {
    const raw = req.get(KEY_HEADER);
    const provider = req.get(PROVIDER_HEADER) || (req.body?.provider ? String(req.body.provider) : undefined);
    if (!raw) return { key: null, provider };
    const key = raw.trim();
    if (key.length < 8 || key.length > 512 || !/^[\x21-\x7e]+$/.test(key)) {
        throw Object.assign(new Error('Malformed API key header.'), { status: 400 });
    }
    return { key, provider };
}

function noStore(_req: Request, res: Response, next: () => void) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    next();
}

async function startServer() {
    const app = express();
    // Behind Render/Fly/NGINX set TRUST_PROXY=1 so rate limits apply per real client IP.
    app.set('trust proxy', process.env.TRUST_PROXY ? Number(process.env.TRUST_PROXY) || process.env.TRUST_PROXY : 'loopback');
    app.disable('x-powered-by');
    app.use(express.json({ limit: '5mb' }));
    const isProd = process.env.NODE_ENV === 'production' || /server\.cjs$/.test(process.argv[1] || '');
    app.use((_req, res, next) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Referrer-Policy', 'no-referrer');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
        res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
        if (isProd) {
            // Strict CSP: no third-party scripts can run in the page that holds the visitor's key.
            res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
            res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        }
        next();
    });

    app.get('/api/health', (_req, res) => {
        const p = listProviders();
        res.json({
            status: 'ok', system: `${ENGINE} OSINT Reconnaissance Server`, version: VERSION,
            byok: true, byokOnly: p.byokOnly,
            aiProvider: p.default, aiConfigured: p.providers.filter(x => x.configured).map(x => x.id),
            timestamp: new Date().toISOString(),
        });
    });

    app.get('/api/providers', (_req, res) => res.json(listProviders()));

    app.post('/api/recon', rateLimit('recon', 10, 60_000), async (req: Request, res: Response) => {
        try {
            const { url, ct = true, wayback = true } = req.body || {};
            res.json(await runRecon(String(url || ''), { ct: !!ct, wayback: !!wayback }));
        } catch (e) { sendError(res, e); }
    });

    app.post('/api/crawl', rateLimit('crawl', 3, 60_000), async (req: Request, res: Response) => {
        try {
            const { url, maxPages = 12, maxDepth = 2 } = req.body || {};
            res.json(await runCrawl(String(url || ''), Number(maxPages), Math.min(Number(maxDepth) || 2, 3)));
        } catch (e) { sendError(res, e); }
    });

    app.use('/api/ai', noStore);

    app.post('/api/ai/analyze', rateLimit('ai', 20, 60_000), async (req: Request, res: Response) => {
        let key: string | null = null;
        try {
            const b = byok(req); key = b.key;
            const { report } = req.body || {};
            if (!report?.target) return res.status(400).json({ error: 'Missing recon report.' });
            res.json(await analyzeReport(report, b.provider, key));
        } catch (e) { sendError(res, e, key); } finally { key = null; }
    });

    app.post('/api/ai/vision', rateLimit('ai', 20, 60_000), async (req: Request, res: Response) => {
        let key: string | null = null;
        try {
            const b = byok(req); key = b.key;
            const { images, pageUrl } = req.body || {};
            if (!Array.isArray(images) || !images.length) return res.status(400).json({ error: 'No images supplied.' });
            res.json(await describeImages(images.map(String), String(pageUrl || ''), b.provider, key));
        } catch (e) { sendError(res, e, key); } finally { key = null; }
    });

    app.post('/api/ai/chat', rateLimit('ai', 20, 60_000), async (req: Request, res: Response) => {
        let key: string | null = null;
        try {
            const b = byok(req); key = b.key;
            const { report, messages } = req.body || {};
            if (!report?.target || !Array.isArray(messages)) return res.status(400).json({ error: 'Missing report or messages.' });
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            await streamDebrief(report, messages, b.provider, t => res.write(t), key);
            res.end();
        } catch (e: any) {
            if (res.headersSent) { res.write(`\n// ERROR: ${redact(e?.message || 'stream failed', key)}`); res.end(); }
            else sendError(res, e, key);
        } finally { key = null; }
    });

    /** Lightweight key check so the UI can confirm a pasted key works (1 tiny completion). */
    app.post('/api/ai/verify', rateLimit('verify', 10, 60_000), async (req: Request, res: Response) => {
        let key: string | null = null;
        try {
            const b = byok(req); key = b.key;
            if (!key) return res.status(400).json({ error: 'No key supplied.' });
            const p = getProvider(b.provider, key);
            try {
                await p.complete([{ role: 'user', content: 'Reply with OK.' }], { maxTokens: 5, temperature: 0, timeoutMs: 20000 });
                res.json({ ok: true, verified: true, provider: p.info.id, model: p.info.model, vision: p.info.vision });
            } catch (e: any) {
                // A slow free-tier queue is not a bad key: accept it but say it is unverified.
                if (e?.status === 504) return res.json({ ok: true, verified: false, provider: p.info.id, model: p.info.model, vision: p.info.vision });
                throw e;
            }
        } catch (e) { sendError(res, e, key); } finally { key = null; }
    });

    // Hardened image/page proxy (SSRF-guarded, size-capped). Used for image thumbnails in the UI.
    app.get('/api/proxy', rateLimit('proxy', 120, 60_000), async (req: Request, res: Response) => {
        try {
            const r = await safeFetch(String(req.query.url || ''), { timeoutMs: 15000, maxBytes: 4 * 1024 * 1024 });
            const type = r.headers.get('content-type') || 'application/octet-stream';
            if (type.startsWith('image/') && !/svg/i.test(type)) {
                res.setHeader('Content-Type', type);
                res.setHeader('Cache-Control', 'public, max-age=3600');
                return res.send(r.body);
            }
            // Non-images are returned as inert text so they can never execute in our origin.
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
            res.setHeader('X-GhostWires-Status', String(r.status));
            res.setHeader('X-GhostWires-Final-URL', r.url);
            res.send(r.text);
        } catch (e) { sendError(res, e); }
    });

    app.use('/api', (_req, res) => res.status(404).json({ error: 'Unknown API route.' }));

    if (!isProd) {
        const { createServer } = await import('vite');
        const vite = await createServer({ server: { middlewareMode: true }, appType: 'spa' });
        app.use(vite.middlewares);
    } else {
        const distPath = path.join(process.cwd(), 'dist');
        app.use(express.static(distPath, { index: false }));
        app.get('/{*splat}', (_req, res) => res.sendFile(path.join(distPath, 'index.html')));
    }

    app.listen(PORT, HOST, () => {
        console.log(`[${ENGINE}] v${VERSION} online → http://localhost:${PORT}`);
        const p = listProviders();
        console.log(`[${ENGINE}] BYOK: enabled${byokOnly() ? ' (server keys ignored — visitors must bring their own)' : ''}; server AI provider: ${p.default ?? 'none'}`);
    });
}

startServer().catch(e => { console.error(e); process.exit(1); });
