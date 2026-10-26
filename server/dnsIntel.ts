// GhostWires Mk.IV — DNS intelligence (Node dns/promises, no third-party resolvers)
import { Resolver } from 'node:dns/promises';
import type { DNSIntel } from '../types';
import { isBlockedIP } from './net';

const resolver = new Resolver({ timeout: 4000, tries: 2 });
if (process.env.DNS_SERVERS) resolver.setServers(process.env.DNS_SERVERS.split(',').map(s => s.trim()).filter(Boolean));

// ---- DNS-over-HTTPS fallback (Cloudflare public resolver, JSON API).
// Used when the local resolver is missing/intercepted (VPN fake-ip, captive DNS, sandboxes).
const DOH = process.env.DOH_URL || 'https://cloudflare-dns.com/dns-query';
const TYPE: Record<string, number> = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, CAA: 257 };
async function doh(name: string, type: keyof typeof TYPE): Promise<string[]> {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 6000);
    try {
        const r = await fetch(`${DOH}?name=${encodeURIComponent(name)}&type=${type}`, { headers: { Accept: 'application/dns-json' }, signal: ctrl.signal });
        if (!r.ok) throw new Error(`DoH HTTP ${r.status}`);
        const j: any = await r.json();
        return (j.Answer || []).filter((a: any) => a.type === TYPE[type]).map((a: any) => String(a.data));
    } finally { clearTimeout(t); }
}
const unq = (s: string) => s.replace(/^"|"$/g, '').replace(/"\s+"/g, '');
const dot = (s: string) => s.replace(/\.$/, '');

async function dohIntel(hostname: string, apex: string, errors: string[]): Promise<Pick<DNSIntel, 'a' | 'aaaa' | 'cname' | 'mx' | 'ns' | 'txt' | 'soa' | 'caa'>> {
    const safe = (n: string, t: keyof typeof TYPE) => doh(n, t).catch(e => { errors.push(`DoH ${t}: ${e.message}`); return [] as string[]; });
    const [a, aaaa, cname, mx, ns, txt, soa, caa] = await Promise.all([
        safe(hostname, 'A'), safe(hostname, 'AAAA'), safe(hostname, 'CNAME'), safe(apex, 'MX'), safe(apex, 'NS'), safe(apex, 'TXT'), safe(apex, 'SOA'), safe(apex, 'CAA'),
    ]);
    const soaParts = soa[0]?.split(/\s+/);
    return {
        a: a.filter(x => /^[\d.]+$/.test(x)), aaaa: aaaa.filter(x => x.includes(':')), cname: cname.map(dot),
        mx: mx.map(m => { const [p, e] = m.split(/\s+/); return { priority: Number(p), exchange: dot(e || '') }; }),
        ns: ns.map(dot), txt: txt.map(unq),
        soa: soaParts ? { nsname: dot(soaParts[0]), hostmaster: dot(soaParts[1]), serial: Number(soaParts[2]) } : null,
        caa,
    };
}

async function attempt<T>(label: string, fn: () => Promise<T>, errors: string[], fallback: T): Promise<T> {
    try { return await fn(); } catch (e: any) {
        if (!['ENODATA', 'ENOTFOUND', 'ENOTIMP', 'ESERVFAIL'].includes(e?.code)) errors.push(`${label}: ${e?.code || e?.message}`);
        return fallback;
    }
}

export async function dnsIntel(hostname: string, apex: string): Promise<DNSIntel> {
    const errors: string[] = [];
    let [a, aaaa, cname, mx, ns, txt, soa, caa, dmarcTxt] = await Promise.all([
        attempt('A', () => resolver.resolve4(hostname), errors, [] as string[]),
        attempt('AAAA', () => resolver.resolve6(hostname), errors, [] as string[]),
        attempt('CNAME', () => resolver.resolveCname(hostname), errors, [] as string[]),
        attempt('MX', () => resolver.resolveMx(apex), errors, [] as { exchange: string; priority: number }[]),
        attempt('NS', () => resolver.resolveNs(apex), errors, [] as string[]),
        attempt('TXT', async () => (await resolver.resolveTxt(apex)).map(c => c.join('')), errors, [] as string[]),
        attempt('SOA', async () => { const s = await resolver.resolveSoa(apex); return { nsname: s.nsname, hostmaster: s.hostmaster, serial: s.serial }; }, errors, null),
        attempt('CAA', async () => (await resolver.resolveCaa(apex)).map((r: any) => `${r.critical} ${Object.keys(r).filter(k => k !== 'critical').map(k => `${k} "${r[k]}"`).join(' ')}`), errors, [] as string[]),
        attempt('DMARC', async () => (await resolver.resolveTxt(`_dmarc.${apex}`)).map(c => c.join('')), errors, [] as string[]),
    ]);

    let base: Pick<DNSIntel, 'a' | 'aaaa' | 'cname' | 'mx' | 'ns' | 'txt' | 'soa' | 'caa'> = { a, aaaa, cname, mx, ns, txt, soa, caa };
    let resolverUsed = 'system';
    const intercepted = (a.length > 0 && a.every(ip => isBlockedIP(ip) || ip.startsWith('198.18.') || ip.startsWith('198.19.'))) || (!ns.length && !soa);
    let dmarcRecords = dmarcTxt;
    if (intercepted || process.env.DNS_MODE === 'doh') {
        try {
            const viaDoh = await dohIntel(hostname, apex, errors);
            if (viaDoh.a.length || viaDoh.ns.length) {
                base = viaDoh; resolverUsed = 'doh';
                dmarcRecords = (await doh(`_dmarc.${apex}`, 'TXT').catch(() => [])).map(unq);
            }
        } catch (e: any) { errors.push(`DoH fallback failed: ${e.message}`); }
    }
    ({ a, aaaa, cname, mx, ns, txt, soa, caa } = base as any);

    const reverse: Record<string, string[]> = {};
    await Promise.all([...a.slice(0, 4), ...aaaa.slice(0, 2)].map(async ip => {
        reverse[ip] = resolverUsed === 'doh'
            ? (ip.includes(':') ? [] : (await doh(ip.split('.').reverse().join('.') + '.in-addr.arpa', 'PTR').catch(() => [])).map(dot))
            : await attempt(`PTR ${ip}`, () => resolver.reverse(ip), errors, []);
    }));

    const spf = txt.find(t => /^v=spf1/i.test(t)) || null;
    const dmarc = dmarcRecords.find(t => /^v=DMARC1/i.test(t)) || null;
    const dmarcPolicy = dmarc?.match(/;\s*p=([a-z]+)/i)?.[1]?.toLowerCase() || null;
    const findings: string[] = [];
    if (!spf) findings.push('No SPF record — domain may be spoofable in email.');
    else if (/\+all\b/.test(spf)) findings.push('SPF uses "+all" (allows any sender) — very weak.');
    else if (/\?all\b/.test(spf)) findings.push('SPF ends in "?all" (neutral) — weak enforcement.');
    else if (/~all\b/.test(spf)) findings.push('SPF soft-fails ("~all") — consider "-all" once verified.');
    if (!dmarc) findings.push('No DMARC record at _dmarc.' + apex + '.');
    else if (dmarcPolicy === 'none') findings.push('DMARC policy is "none" (monitor only).');
    if (!mx.length) findings.push('No MX records — domain does not receive mail (or uses null MX).');
    if (!caa.length) findings.push('No CAA records — any CA may issue certificates for this domain.');

    // SaaS footprint: verification tokens + SPF includes reveal third-party services in use.
    const saas = new Set<string>();
    const SAAS: [RegExp, string][] = [
        [/^MS=|include:spf\.protection\.outlook\.com/i, 'Microsoft 365'], [/^google-site-verification|include:_spf\.google\.com/i, 'Google Workspace / Search Console'],
        [/^apple-domain-verification/i, 'Apple'], [/^facebook-domain-verification/i, 'Meta Business'], [/^atlassian-domain-verification/i, 'Atlassian'],
        [/^docusign/i, 'DocuSign'], [/^adobe-idp-site-verification/i, 'Adobe'], [/^stripe-verification/i, 'Stripe'], [/include:sendgrid\.net/i, 'SendGrid'],
        [/include:mailgun\.org/i, 'Mailgun'], [/include:servers\.mcsv\.net|^mailchimp/i, 'Mailchimp'], [/include:_spf\.salesforce\.com|^00D[a-zA-Z0-9]{12,}/, 'Salesforce'],
        [/include:.*hubspot|^hubspot/i, 'HubSpot'], [/include:amazonses\.com|^amazonses/i, 'Amazon SES'], [/include:zoho|^zoho-verification/i, 'Zoho'],
        [/^slack-domain-verification/i, 'Slack'], [/^zoom-domain-verification|ZOOM_verify/i, 'Zoom'], [/^dropbox-domain-verification/i, 'Dropbox'],
        [/^globalsign|^_globalsign/i, 'GlobalSign'], [/^TAILSCALE-/i, 'Tailscale'], [/^openai-domain-verification/i, 'OpenAI'], [/^cursor-domain-verification/i, 'Cursor'],
    ];
    for (const t of txt) {
        const hits = SAAS.filter(([r]) => r.test(t));
        hits.forEach(h => saas.add(h[1]));
        if (!hits.length) { const m = t.match(/^([a-z0-9-]+?)[-_](domain|site)[-_]verification/i); if (m) saas.add(m[1].replace(/^./, c => c.toUpperCase())); }
    }

    return {
        saasFootprint: [...saas].sort(),
        a, aaaa, cname, mx: mx.sort((x, y) => x.priority - y.priority), ns, txt, soa, caa, reverse,
        emailSecurity: { spf, dmarc, dmarcPolicy, findings }, errors, resolver: resolverUsed as 'system' | 'doh',
    };
}
