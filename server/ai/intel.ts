// GhostWires Mk.IV — AI layer. The model only interprets REAL facts gathered by the
// deterministic pipeline; it is explicitly told not to invent infrastructure.
import type { ReconReport, AIAnalysis, ChatMessage } from '../../types';
import { getProvider, redact, type ChatTurn } from './providers';
import { safeFetch } from '../net';

/** Compact, token-friendly digest of verified facts. */
export function factDigest(r: ReconReport) {
    return {
        target: { url: r.target.finalUrl, status: r.target.status, ips: r.target.resolvedIPs, redirects: r.target.redirectChain.length },
        dns: { a: r.dns.a, aaaa: r.dns.aaaa, ns: r.dns.ns, mx: r.dns.mx.map(m => m.exchange), spf: r.dns.emailSecurity.spf, dmarcPolicy: r.dns.emailSecurity.dmarcPolicy, emailFindings: r.dns.emailSecurity.findings, caa: r.dns.caa.length, ptr: r.dns.reverse },
        tls: r.tls.available ? { issuer: r.tls.issuer, protocol: r.tls.protocol, daysRemaining: r.tls.daysRemaining, sanCount: r.tls.sans.length, trusted: r.tls.authorized } : { error: r.tls.error },
        headers: { grade: r.headers.grade, score: r.headers.score, missing: r.headers.findings.filter(f => !f.present).map(f => f.header), weak: r.headers.findings.filter(f => f.present && f.severity === 'low').map(f => `${f.header}: ${f.note}`), disclosure: r.headers.disclosure, insecureCookies: r.headers.cookies.filter(c => !c.secure || !c.httpOnly).map(c => c.name) },
        tech: r.tech.map(t => `${t.name}${t.version ? ' ' + t.version : ''} [${t.category}]`),
        contacts: { emails: r.contacts.emails.length, phones: r.contacts.phones.length, socials: r.contacts.socials.map(s => s.platform), addresses: r.contacts.addresses.length },
        surface: { robotsDisallow: r.robots.disallow.slice(0, 20), sitemapUrls: r.sitemap.urlCount, securityTxt: r.securityTxt.found, ctSubdomains: r.ct.subdomains.length, waybackFirstSeen: r.wayback.firstSeen, forms: r.forms.length, passwordForms: r.forms.filter(f => f.hasPassword).length },
        meta: { title: r.meta.title, description: r.meta.description, lang: r.meta.lang, h1: r.meta.headings.h1, wordCount: r.meta.wordCount, og: r.meta.og, jsonLd: r.meta.jsonLdTypes, canonical: r.meta.canonical, robotsMeta: r.meta.robotsMeta },
        accessibility: r.accessibility,
        links: { internal: r.links.filter(l => l.type === 'internal').length, external: r.links.filter(l => l.type === 'external').length, social: r.links.filter(l => l.type === 'social').length },
        images: { total: r.images.length, missingAlt: r.images.filter(i => !i.alt).length },
    };
}

const ANALYST_SYSTEM = `You are GhostWires Mk.IV, a defensive OSINT analyst. You receive VERIFIED facts collected from public sources (DNS, TLS handshake, HTTP headers, HTML) plus a page text sample.
Rules:
- Never invent IPs, hosts, CVEs, owners, locations, people or technologies that are not in the facts.
- If something is unknown, say "not observed".
- Do not recommend controls the facts show are already in place (e.g. TLS 1.3 already negotiated, a header already present).
- Frame security observations as defensive hygiene recommendations, never as exploitation steps.
- Output ONLY one JSON object, no markdown fences.`;

const ANALYSIS_SHAPE = `{
  "summary": "3-5 sentence executive summary of who/what this site is and its posture",
  "sentiment": number between -1 and 1 for the page text tone,
  "readability": "e.g. 'Plain English (GCSE level)'",
  "language": "e.g. 'English (en-GB)'",
  "keyTopics": ["max 8 topics"],
  "entities": ["organisations/products/places named in the text, max 10"],
  "seoNarrative": "2-3 sentences on SEO/meta/social-card quality based on meta facts",
  "a11yNarrative": "2-3 sentences interpreting the accessibility audit",
  "securityNarrative": "2-4 sentences on header grade, TLS, email auth (SPF/DMARC), info disclosure",
  "recommendations": ["5-8 concise, prioritised defensive recommendations"]
}`;

function parseJson(text: string): any {
    let t = text.trim().replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '');
    const start = t.indexOf('{'), end = t.lastIndexOf('}');
    if (start >= 0 && end > start) t = t.slice(start, end + 1);
    return JSON.parse(t);
}

export async function analyzeReport(report: ReconReport, providerId?: string, byokKey?: string | null): Promise<AIAnalysis> {
    const p = getProvider(providerId, byokKey);
    const messages: ChatTurn[] = [
        { role: 'system', content: ANALYST_SYSTEM },
        { role: 'user', content: `VERIFIED FACTS:\n${JSON.stringify(factDigest(report))}\n\nPAGE TEXT SAMPLE (truncated):\n${report.meta.textSample.slice(0, 4500)}\n\nReturn JSON exactly in this shape:\n${ANALYSIS_SHAPE}` },
    ];
    let raw = await p.complete(messages, { json: true, maxTokens: 1800, temperature: 0.2 });
    let data: any;
    try { data = parseJson(raw); } catch {
        raw = await p.complete([...messages, { role: 'assistant', content: raw }, { role: 'user', content: 'That was not valid JSON. Reply again with ONLY the JSON object.' }], { json: true, maxTokens: 1800, temperature: 0 });
        data = parseJson(raw);
    }
    const arr = (v: any) => Array.isArray(v) ? v.map(String).slice(0, 12) : [];
    const sentiment = Math.max(-1, Math.min(1, Number(data.sentiment) || 0));
    return {
        provider: p.info.id, model: p.info.model,
        summary: String(data.summary || ''), sentiment,
        readability: String(data.readability || 'not observed'), language: String(data.language || report.meta.lang || 'not observed'),
        keyTopics: arr(data.keyTopics), entities: arr(data.entities),
        seoNarrative: String(data.seoNarrative || ''), a11yNarrative: String(data.a11yNarrative || ''),
        securityNarrative: String(data.securityNarrative || ''), recommendations: arr(data.recommendations),
    };
}

const VISION_MIME = /^image\/(png|jpe?g|webp|gif)$/i;
export async function describeImages(srcs: string[], pageUrl: string, providerId?: string, byokKey?: string | null) {
    const p = getProvider(providerId, byokKey);
    if (!p.describeImage) {
        return { provider: p.info.id, vision: false, results: srcs.map(src => ({ src, detailedDescription: '', error: `${p.info.label} model has no vision support — switch provider to use image analysis.` })) };
    }
    const results: { src: string; detailedDescription: string; error?: string }[] = [];
    for (const src of srcs.slice(0, 6)) {
        try {
            const res = await safeFetch(src, { timeoutMs: 12000, maxBytes: 900 * 1024, accept: 'image/png,image/jpeg,image/webp,image/gif' });
            const mime = (res.headers.get('content-type') || '').split(';')[0].trim();
            if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
            if (!VISION_MIME.test(mime)) throw new Error(`unsupported format ${mime || 'unknown'}`);
            if (res.body.length > 750 * 1024) throw new Error('image too large for vision model');
            const text = await p.describeImage(`This image appears on ${pageUrl}. In ONE factual sentence, describe what it visibly shows (logo, person, product, chart, text). Do not guess identities of people.`, { mime, base64: res.body.toString('base64') });
            results.push({ src, detailedDescription: text });
        } catch (e: any) {
            results.push({ src, detailedDescription: '', error: redact(e?.message || 'vision failed', byokKey) });
        }
    }
    return { provider: p.info.id, vision: true, results };
}

export async function streamDebrief(report: ReconReport, history: ChatMessage[], providerId: string | undefined, onDelta: (t: string) => void, byokKey?: string | null) {
    const p = getProvider(providerId, byokKey);
    const system = `You are GhostWires Mk.IV's intelligence debriefing module. Answer ONLY from the verified recon report below; if the answer is not in it, say it was not observed in this scan. Be concise and defensive in framing — never provide exploitation instructions. Refer to it as "the report".\n\nREPORT FACTS:\n${JSON.stringify(factDigest(report))}\n\nCONTACTS: ${JSON.stringify(report.contacts)}\nSUBDOMAINS (CT): ${report.ct.subdomains.slice(0, 80).join(', ')}\nTECH EVIDENCE: ${JSON.stringify(report.tech)}`;
    const turns: ChatTurn[] = [{ role: 'system', content: system }, ...history.slice(-12).map(m => ({ role: (m.role === 'model' ? 'assistant' : 'user') as ChatTurn['role'], content: m.content.slice(0, 4000) }))];
    await p.stream(turns, onDelta);
}
