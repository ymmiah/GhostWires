// GhostWires Mk.IV — minimal in-memory fixed-window rate limiter (per client IP)
import type { Request, Response, NextFunction } from 'express';

export function rateLimit(name: string, max: number, windowMs: number) {
    const hits = new Map<string, { count: number; reset: number }>();
    setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (v.reset < now) hits.delete(k); }, windowMs).unref();
    return (req: Request, res: Response, next: NextFunction) => {
        const key = `${req.ip}`;
        const now = Date.now();
        const entry = hits.get(key);
        if (!entry || entry.reset < now) { hits.set(key, { count: 1, reset: now + windowMs }); return next(); }
        if (++entry.count > max) {
            res.setHeader('Retry-After', Math.ceil((entry.reset - now) / 1000));
            return res.status(429).json({ error: `Rate limit for ${name} exceeded (${max} per ${windowMs / 1000}s). Slow down — GhostWires is polite by design.` });
        }
        next();
    };
}
