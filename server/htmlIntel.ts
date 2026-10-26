// GhostWires Mk.IV — HTML parsing: meta, links, images, forms, contacts, a11y checks
import * as cheerio from 'cheerio';
import type { PageMeta, ExtractedLink, ExtractedImage, ContactIntel, A11yAudit, A11yIssue } from '../types';
import { registrableDomain } from './net';

const SOCIAL: [string, RegExp][] = [
    ['X / Twitter', /^(https?:)?\/\/(www\.)?(twitter|x)\.com\/(?!intent|share|home)[A-Za-z0-9_]{1,30}\/?$/i],
    ['LinkedIn', /^(https?:)?\/\/([a-z]{2,3}\.)?linkedin\.com\/(company|in|school|showcase)\/[^/?#]+/i],
    ['GitHub', /^(https?:)?\/\/(www\.)?github\.com\/[A-Za-z0-9-]+\/?$/i],
    ['Facebook', /^(https?:)?\/\/(www\.|m\.)?facebook\.com\/(?!sharer|share|dialog|plugins|tr\b)[^/?#]+/i],
    ['Instagram', /^(https?:)?\/\/(www\.)?instagram\.com\/(?!p\/|explore)[^/?#]+/i],
    ['YouTube', /^(https?:)?\/\/(www\.)?youtube\.com\/(@|c\/|channel\/|user\/)[^/?#]+/i],
    ['TikTok', /^(https?:)?\/\/(www\.)?tiktok\.com\/@[^/?#]+/i],
    ['Mastodon', /^(https?:)?\/\/[a-z0-9.-]+\/@[A-Za-z0-9_]+$/i],
    ['Bluesky', /^(https?:)?\/\/bsky\.app\/profile\/[^/?#]+/i],
    ['Threads', /^(https?:)?\/\/(www\.)?threads\.net\/@[^/?#]+/i],
    ['Pinterest', /^(https?:)?\/\/([a-z]{2}\.)?pinterest\.[a-z.]+\/[^/?#]+\/?$/i],
    ['Reddit', /^(https?:)?\/\/(www\.)?reddit\.com\/(r|user|u)\/[^/?#]+/i],
    ['Discord', /^(https?:)?\/\/(www\.)?(discord\.gg|discord\.com\/invite)\/[^/?#]+/i],
    ['Telegram', /^(https?:)?\/\/(t\.me|telegram\.me)\/[^/?#]+/i],
    ['WhatsApp', /^(https?:)?\/\/(wa\.me|api\.whatsapp\.com)\//i],
];

const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}/g;
const BAD_EMAIL = /\.(png|jpe?g|gif|svg|webp|css|js)$|^(example|user|name|email|your)@|@(example|sentry|domain|email)\.|wixpress\.com$|sentry\.io$/i;
const PHONE_RE = /(?:\+\d{1,3}[\s.-]?)?(?:\(\d{1,4}\)[\s.-]?)?\d{2,4}[\s.-]\d{3,4}[\s.-]?\d{3,4}/g;

function deobfuscate(text: string): string {
    return text
        .replace(/\s*[[(]\s*at\s*[\])]\s*/gi, '@')
        .replace(/\s*[[(]\s*dot\s*[\])]\s*/gi, '.');
}

export interface ParsedPage {
    meta: PageMeta;
    links: ExtractedLink[];
    images: ExtractedImage[];
    scripts: string[];
    forms: { action: string; method: string; inputs: number; hasPassword: boolean }[];
    contacts: ContactIntel;
    accessibility: A11yAudit;
    subfolders: string[];
}

export function parseHtml(html: string, pageUrl: string): ParsedPage {
    const $ = cheerio.load(html);
    const base = new URL(pageUrl);
    const apex = registrableDomain(base.hostname);
    const metaContent = (sel: string) => ($(sel).attr('content') || '').trim();

    // --- Meta
    const og: Record<string, string> = {};
    $('meta[property^="og:"]').each((_, el) => { og[$(el).attr('property')!.slice(3)] = ($(el).attr('content') || '').slice(0, 300); });
    const twitter: Record<string, string> = {};
    $('meta[name^="twitter:"]').each((_, el) => { twitter[$(el).attr('name')!.slice(8)] = ($(el).attr('content') || '').slice(0, 300); });
    const jsonLdTypes = new Set<string>();
    const jsonLdBlobs: any[] = [];
    $('script[type="application/ld+json"]').each((_, el) => {
        try {
            const data = JSON.parse($(el).contents().text());
            const walk = (n: any) => { if (!n || typeof n !== 'object') return; if (Array.isArray(n)) return n.forEach(walk); if (n['@type']) [].concat(n['@type']).forEach((t: string) => jsonLdTypes.add(t)); jsonLdBlobs.push(n); if (n['@graph']) walk(n['@graph']); };
            walk(data);
        } catch { /* ignore malformed */ }
    });
    const scripts = $('script[src]').map((_, el) => $(el).attr('src') || '').get().filter(Boolean);

    const bodyClone = $('body').clone();
    bodyClone.find('script,style,noscript,svg,template').remove();
    const text = bodyClone.text().replace(/\s+/g, ' ').trim();

    const meta: PageMeta = {
        title: $('title').first().text().trim(),
        description: metaContent('meta[name="description"]'),
        keywords: metaContent('meta[name="keywords"]').split(',').map(s => s.trim()).filter(Boolean).slice(0, 30),
        lang: $('html').attr('lang') || '',
        canonical: $('link[rel="canonical"]').attr('href') || '',
        generator: metaContent('meta[name="generator"]'),
        robotsMeta: metaContent('meta[name="robots"]'),
        og, twitter,
        headings: {
            h1: $('h1').map((_, el) => $(el).text().replace(/\s+/g, ' ').trim()).get().filter(Boolean).slice(0, 10),
            h2: $('h2').map((_, el) => $(el).text().replace(/\s+/g, ' ').trim()).get().filter(Boolean).slice(0, 20),
        },
        wordCount: text ? text.split(' ').length : 0,
        textSample: text.slice(0, 6000),
        jsonLdTypes: [...jsonLdTypes].slice(0, 20),
    };

    // --- Links
    const seen = new Set<string>();
    const links: ExtractedLink[] = [];
    const socials = new Map<string, { platform: string; url: string }>();
    const emails = new Set<string>();
    const phones = new Set<string>();
    const folders = new Set<string>();
    $('a[href]').each((_, el) => {
        const hrefRaw = ($(el).attr('href') || '').trim();
        const label = $(el).text().replace(/\s+/g, ' ').trim().slice(0, 120);
        if (/^mailto:/i.test(hrefRaw)) { const e = decodeURIComponent(hrefRaw.slice(7).split('?')[0]).trim().toLowerCase(); if (e.includes('@')) emails.add(e); return; }
        if (/^tel:/i.test(hrefRaw)) { const p = decodeURIComponent(hrefRaw.slice(4)).replace(/[^\d+]/g, ''); if (p.length >= 7) phones.add(p); return; }
        if (!hrefRaw || hrefRaw.startsWith('#') || /^(javascript|data):/i.test(hrefRaw)) return;
        let abs: URL;
        try { abs = new URL(hrefRaw, base); } catch { return; }
        if (!/^https?:$/.test(abs.protocol)) return;
        abs.hash = '';
        const href = abs.href;
        if (seen.has(href)) return;
        seen.add(href);
        const internal = registrableDomain(abs.hostname) === apex;
        const social = internal ? undefined : SOCIAL.find(([, r]) => r.test(href));
        if (social) socials.set(href.replace(/\/$/, '').toLowerCase(), { platform: social[0], url: href });
        links.push({ href, text: label, type: social ? 'social' : internal ? 'internal' : 'external' });
        if (internal) {
            const seg = abs.pathname.split('/').filter(Boolean);
            if (seg.length > 1 || (seg.length === 1 && !seg[0].includes('.'))) folders.add('/' + seg[0] + '/');
        }
    });
    // sameAs from JSON-LD = owner-declared social profiles (high-value OSINT)
    for (const n of jsonLdBlobs) {
        for (const s of ([] as unknown[]).concat(n.sameAs || [])) {
            if (typeof s !== 'string') continue;
            const plat = SOCIAL.find(([, r]) => r.test(s));
            socials.set(s.replace(/\/$/, '').toLowerCase(), { platform: plat?.[0] || 'Profile (schema.org sameAs)', url: s });
        }
        if (typeof n.email === 'string') emails.add(n.email.replace(/^mailto:/i, '').toLowerCase());
        if (typeof n.telephone === 'string') phones.add(n.telephone.trim());
    }

    // --- Text-based contacts
    const searchable = deobfuscate(text + ' ' + $('footer').text());
    const all = (src: string, re: RegExp): string[] => Array.from(src.match(re) ?? []);
    all(searchable, EMAIL_RE).forEach(e => emails.add(e.toLowerCase()));
    all(html, EMAIL_RE).slice(0, 200).forEach(e => emails.add(e.toLowerCase()));
    all(searchable, PHONE_RE).forEach(p => {
        const digits = p.replace(/\D/g, '');
        if (digits.length >= 9 && digits.length <= 15 && !/^(19|20)\d{2}\D*(19|20)\d{2}/.test(p.trim())) phones.add(p.trim());
    });
    const addresses = new Set<string>();
    $('address').each((_, el) => { const t = $(el).text().replace(/\s+/g, ' ').trim(); if (t) addresses.add(t.slice(0, 200)); });
    for (const n of jsonLdBlobs) {
        const a = n.address;
        if (a && typeof a === 'object' && !Array.isArray(a)) {
            const parts = [a.streetAddress, a.addressLocality, a.addressRegion, a.postalCode, a.addressCountry?.name || a.addressCountry].filter(x => typeof x === 'string');
            if (parts.length) addresses.add(parts.join(', '));
        } else if (typeof a === 'string') addresses.add(a);
    }
    // UK postcode heuristic
    all(text, /\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b/g).slice(0, 5).forEach(pc => {
        const idx = text.indexOf(pc);
        addresses.add(text.slice(Math.max(0, idx - 80), idx + pc.length).replace(/^\S*\s/, '').trim());
    });
    const phoneDedup = new Map<string, string>();
    phones.forEach(p => { const k = p.replace(/\D/g, '').slice(-9); if (!phoneDedup.has(k)) phoneDedup.set(k, p); });

    const contacts: ContactIntel = {
        emails: [...emails].filter(e => !BAD_EMAIL.test(e)).slice(0, 50),
        phones: [...phoneDedup.values()].slice(0, 25),
        socials: [...socials.values()].slice(0, 40),
        addresses: [...addresses].slice(0, 10),
    };

    // --- Images
    const imgSeen = new Set<string>();
    const images: ExtractedImage[] = [];
    $('img').each((_, el) => {
        const src = $(el).attr('src') || $(el).attr('data-src') || ($(el).attr('srcset') || '').split(/\s+/)[0];
        if (!src || src.startsWith('data:')) return;
        try { const abs = new URL(src, base).href; if (!imgSeen.has(abs)) { imgSeen.add(abs); images.push({ src: abs, alt: ($(el).attr('alt') || '').trim() }); } } catch { /* skip */ }
    });
    if (og.image) { try { const abs = new URL(og.image, base).href; if (!imgSeen.has(abs)) images.unshift({ src: abs, alt: 'og:image' }); } catch { /* skip */ } }

    // --- Forms
    const forms = $('form').map((_, el) => ({
        action: (() => { try { return new URL($(el).attr('action') || '', base).href; } catch { return $(el).attr('action') || ''; } })(),
        method: ($(el).attr('method') || 'get').toUpperCase(),
        inputs: $(el).find('input,select,textarea').length,
        hasPassword: $(el).find('input[type="password"]').length > 0,
    })).get().slice(0, 20);

    // --- Deterministic accessibility checks (WCAG-inspired heuristics)
    const issues: A11yIssue[] = [];
    const add = (impact: A11yIssue['impact'], description: string, count: number) => { if (count > 0) issues.push({ impact, description, count }); };
    add('critical', 'Images missing an alt attribute', $('img:not([alt])').length);
    add('serious', '<html> element has no lang attribute', meta.lang ? 0 : 1);
    add('serious', 'Page has no <title>', meta.title ? 0 : 1);
    const unlabeled = $('input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="image"]),select,textarea').filter((_, el) => {
        const id = $(el).attr('id');
        return !$(el).attr('aria-label') && !$(el).attr('aria-labelledby') && !$(el).attr('title') && !(id && $(`label[for="${id}"]`).length) && !$(el).closest('label').length;
    }).length;
    add('critical', 'Form controls without an accessible label', unlabeled);
    add('serious', 'Links with no discernible text', $('a[href]').filter((_, el) => !$(el).text().trim() && !$(el).attr('aria-label') && !$(el).find('img[alt]:not([alt=""])').length && !$(el).attr('title')).length);
    add('serious', 'Buttons with no discernible text', $('button').filter((_, el) => !$(el).text().trim() && !$(el).attr('aria-label') && !$(el).attr('title')).length);
    add('moderate', 'No <h1> heading on the page', meta.headings.h1.length ? 0 : 1);
    add('minor', 'Multiple <h1> headings', meta.headings.h1.length > 1 ? meta.headings.h1.length : 0);
    add('moderate', 'No <main> landmark', $('main,[role="main"]').length ? 0 : 1);
    const vp = metaContent('meta[name="viewport"]');
    add('moderate', 'Viewport blocks zoom (user-scalable=no / maximum-scale=1)', /user-scalable\s*=\s*(no|0)|maximum-scale\s*=\s*1(\.0)?\b/i.test(vp) ? 1 : 0);
    add('minor', 'No viewport meta tag (mobile rendering)', vp ? 0 : 1);
    add('minor', 'Positive tabindex values (disrupts focus order)', $('[tabindex]').filter((_, el) => Number($(el).attr('tabindex')) > 0).length);
    add('minor', 'iframes without a title', $('iframe:not([title])').length);
    const penalty = issues.reduce((s, i) => s + ({ critical: 15, serious: 10, moderate: 5, minor: 2 }[i.impact]) * Math.min(i.count, 3), 0);

    return {
        meta, links: links.slice(0, 500), images: images.slice(0, 60), scripts, forms, contacts,
        accessibility: { score: Math.max(0, 100 - penalty), issues },
        subfolders: [...folders].slice(0, 60),
    };
}
