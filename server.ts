// GhostWires Mk.IV — Express API + Vite dev middleware
// Author: Yasin Mohammed Miah, Student of BCU, BSc Computing Top-Up (Hons)
import './server/env';
import path from 'node:path';
import express, { type Request, type Response } from 'express';
import { runRecon, runCrawl, ENGINE, VERSION } from './server/recon';
import { safeFetch, TargetError } from './server/net';
import { rateLimit } from './server/rateLimit';
import { listProviders } from './server/ai/providers';
import { analyzeReport, describeImages, streamDebrief } from './server/ai/intel';

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';

function sendError(res: Response, err: any) {
    const status = err instanceof TargetError ? err.status : (err?.status || 500);
    if (status >= 500) console.error('[GhostWires]', err?.message || err);
    if (!res.headersSent) res.status(status).json({ error: err?.message || 'Internal error' });
}

async function startServer() {
    const app = express();
    app.set('trust proxy', 'loopback');
    app.disable('x-powered-by');
    app.use(express.json({ limit: '5mb' }));
    app.use((_req, res, next) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Referrer-Policy', 'no-referrer');
        res.setHeader('X-Frame-Options', 'DENY');
        next();
    });

    app.get('/api/health', (_req, res) => {
        const p = listProviders();
        res.json({
            status: 'ok', system: `${ENGINE} OSINT Reconnaissance Server`, version: VERSION,
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

    app.post('/api/ai/analyze', rateLimit('ai', 20, 60_000), async (req: Request, res: Response) => {
        try {
            const { report, provider } = req.body || {};
            if (!report?.target) return res.status(400).json({ error: 'Missing recon report.' });
            res.json(await analyzeReport(report, provider));
        } catch (e) { sendError(res, e); }
    });

    app.post('/api/ai/vision', rateLimit('ai', 20, 60_000), async (req: Request, res: Response) => {
        try {
            const { images, pageUrl, provider } = req.body || {};
            if (!Array.isArray(images) || !images.length) return res.status(400).json({ error: 'No images supplied.' });
            res.json(await describeImages(images.map(String), String(pageUrl || ''), provider));
        } catch (e) { sendError(res, e); }
    });

    app.post('/api/ai/chat', rateLimit('ai', 20, 60_000), async (req: Request, res: Response) => {
        const { report, messages, provider } = req.body || {};
        if (!report?.target || !Array.isArray(messages)) return res.status(400).json({ error: 'Missing report or messages.' });
        try {
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.setHeader('Cache-Control', 'no-cache');
            await streamDebrief(report, messages, provider, t => res.write(t));
            res.end();
        } catch (e: any) {
            if (res.headersSent) { res.write(`\n// ERROR: ${e?.message || 'stream failed'}`); res.end(); }
            else sendError(res, e);
        }
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

    const isProd = process.env.NODE_ENV === 'production' || /server\.cjs$/.test(process.argv[1] || '');
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
        console.log(`[${ENGINE}] AI provider: ${p.default ?? 'none (deterministic OSINT only)'}`);
    });
}

startServer().catch(e => { console.error(e); process.exit(1); });
