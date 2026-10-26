// GhostWires Mk.IV — HTTP security header audit
import type { HeadersAudit, HeaderFinding, Severity } from '../types';

interface Check { header: string; weight: number; missing: Severity; note: string; validate?: (v: string) => string | null; }

const CHECKS: Check[] = [
    { header: 'strict-transport-security', weight: 20, missing: 'high', note: 'HSTS forces HTTPS and prevents SSL-stripping.',
      validate: v => { const m = v.match(/max-age=(\d+)/i); if (!m) return 'max-age missing'; if (+m[1] < 15552000) return `max-age ${m[1]}s is under 180 days`; return null; } },
    { header: 'content-security-policy', weight: 25, missing: 'high', note: 'CSP mitigates XSS and data injection.',
      validate: v => /unsafe-inline|unsafe-eval/.test(v) && !/nonce-|strict-dynamic/.test(v) ? "allows 'unsafe-inline'/'unsafe-eval' without nonces" : (/default-src\s+\*/.test(v) ? 'default-src is wildcard' : null) },
    { header: 'x-frame-options', weight: 10, missing: 'medium', note: 'Prevents clickjacking (or use CSP frame-ancestors).' },
    { header: 'x-content-type-options', weight: 10, missing: 'medium', note: 'Should be "nosniff" to block MIME sniffing.',
      validate: v => v.toLowerCase().includes('nosniff') ? null : 'value is not nosniff' },
    { header: 'referrer-policy', weight: 10, missing: 'low', note: 'Controls how much referrer data leaks to other sites.',
      validate: v => /unsafe-url/i.test(v) ? 'unsafe-url leaks full URLs' : null },
    { header: 'permissions-policy', weight: 10, missing: 'low', note: 'Restricts powerful browser features (camera, geolocation…).' },
    { header: 'cross-origin-opener-policy', weight: 5, missing: 'info', note: 'Isolates browsing context from cross-origin windows.' },
    { header: 'cross-origin-resource-policy', weight: 5, missing: 'info', note: 'Limits who can embed this resource.' },
    { header: 'cross-origin-embedder-policy', weight: 5, missing: 'info', note: 'Required for cross-origin isolation.' },
];

const DISCLOSURE = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'x-drupal-cache', 'x-varnish', 'via', 'x-runtime', 'x-served-by', 'x-cache'];

export function auditHeaders(headers: Headers, setCookies: string[], isHttps: boolean): HeadersAudit {
    const raw: Record<string, string> = {};
    headers.forEach((v, k) => { if (k !== 'set-cookie') raw[k] = v; });
    const findings: HeaderFinding[] = [];
    let score = 0;
    const total = CHECKS.reduce((s, c) => s + c.weight, 0);

    for (const c of CHECKS) {
        let value = headers.get(c.header) ?? undefined;
        if (c.header === 'x-frame-options' && !value && /frame-ancestors/i.test(headers.get('content-security-policy') || '')) {
            findings.push({ header: c.header, present: true, value: '(via CSP frame-ancestors)', severity: 'info', note: 'Covered by CSP frame-ancestors.' });
            score += c.weight; continue;
        }
        if (c.header === 'strict-transport-security' && !isHttps) {
            findings.push({ header: c.header, present: false, severity: 'high', note: 'Site served over plain HTTP — HSTS cannot apply.' });
            continue;
        }
        if (!value) { findings.push({ header: c.header, present: false, severity: c.missing, note: c.note }); continue; }
        const problem = c.validate?.(value) || null;
        if (problem) { score += c.weight / 2; findings.push({ header: c.header, present: true, value, severity: 'low', note: `Weak: ${problem}.` }); }
        else { score += c.weight; findings.push({ header: c.header, present: true, value, severity: 'info', note: 'OK' }); }
    }

    const disclosure = DISCLOSURE.filter(h => headers.get(h)).map(h => ({ header: h, value: headers.get(h)! }));
    const cookies = setCookies.map(c => {
        const [pair, ...attrs] = c.split(';').map(s => s.trim());
        const low = attrs.map(a => a.toLowerCase());
        return {
            name: pair.split('=')[0],
            secure: low.includes('secure'),
            httpOnly: low.includes('httponly'),
            sameSite: low.find(a => a.startsWith('samesite='))?.split('=')[1] || null,
        };
    });
    const pct = Math.round((score / total) * 100);
    const grade = pct >= 95 ? 'A+' : pct >= 80 ? 'A' : pct >= 65 ? 'B' : pct >= 50 ? 'C' : pct >= 35 ? 'D' : pct >= 20 ? 'E' : 'F';
    return { score: pct, grade, findings, disclosure, cookies, raw };
}
