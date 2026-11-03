// GhostWires Mk.IV — deterministic technology fingerprinting from HTML + headers + cookies
import * as cheerio from 'cheerio';
import type { TechHit } from '../types';

interface Sig {
    name: string;
    category: string;
    html?: RegExp[];      // match against raw HTML
    script?: RegExp[];    // match against <script src>
    header?: [string, RegExp][];
    cookie?: RegExp[];
    meta?: RegExp;        // match against <meta name=generator>
    version?: RegExp;     // capture group 1 = version, run over html+scripts+headers
}

const SIGS: Sig[] = [
    // CMS / site builders
    { name: 'WordPress', category: 'CMS', html: [/wp-content\//i, /wp-includes\//i], meta: /wordpress/i, version: /WordPress\s?([\d.]+)/i },
    { name: 'Drupal', category: 'CMS', html: [/Drupal\.settings/i, /\/sites\/default\/files/i], header: [['x-generator', /drupal/i]], meta: /drupal/i, version: /Drupal\s?([\d.]+)/i },
    { name: 'Joomla', category: 'CMS', html: [/\/media\/jui\//i, /com_content/i], meta: /joomla/i },
    { name: 'Ghost', category: 'CMS', meta: /^ghost/i, version: /Ghost\s([\d.]+)/i },
    { name: 'Shopify', category: 'E-commerce', html: [/cdn\.shopify\.com/i, /Shopify\.theme/i], header: [['x-shopid', /./]] },
    { name: 'WooCommerce', category: 'E-commerce', html: [/woocommerce/i] },
    { name: 'Magento', category: 'E-commerce', html: [/Mage\.Cookies/i, /\/static\/version\d+\/frontend\//i], cookie: [/^frontend=/i] },
    { name: 'BigCommerce', category: 'E-commerce', html: [/cdn\d*\.bigcommerce\.com/i] },
    { name: 'Squarespace', category: 'Site builder', html: [/static\d*\.squarespace\.com/i], meta: /squarespace/i },
    { name: 'Wix', category: 'Site builder', html: [/static\.wixstatic\.com/i, /wix-code/i], header: [['x-wix-request-id', /./]] },
    { name: 'Webflow', category: 'Site builder', html: [/data-wf-page/i, /assets\.website-files\.com/i], meta: /webflow/i },
    { name: 'Framer', category: 'Site builder', html: [/framerusercontent\.com/i, /__framer/i], meta: /framer/i },
    { name: 'HubSpot CMS', category: 'CMS', html: [/hs-scripts\.com/i, /hubspot/i] },
    // JS frameworks
    { name: 'Next.js', category: 'JS framework', html: [/__NEXT_DATA__/, /\/_next\/static\//], header: [['x-powered-by', /next\.js/i]] },
    { name: 'Nuxt', category: 'JS framework', html: [/__NUXT__/, /\/_nuxt\//] },
    { name: 'Gatsby', category: 'JS framework', html: [/___gatsby/], meta: /gatsby/i },
    { name: 'Astro', category: 'JS framework', html: [/astro-island/i], meta: /astro/i },
    { name: 'SvelteKit', category: 'JS framework', html: [/__sveltekit/i, /\/_app\/immutable\//] },
    { name: 'Remix', category: 'JS framework', html: [/__remixContext/] },
    { name: 'Angular', category: 'JS framework', html: [/ng-version="([\d.]+)"/, /\bng-app\b/], version: /ng-version="([\d.]+)"/ },
    { name: 'React', category: 'JS library', html: [/data-reactroot/, /react-dom/i, /__REACT_DEVTOOLS/], script: [/react(\.production)?(\.min)?\.js/i] },
    { name: 'Vue.js', category: 'JS framework', html: [/data-v-[0-9a-f]{8}/, /\bv-cloak\b/], script: [/vue(\.runtime)?(\.global)?(\.prod)?(\.min)?\.js/i] },
    { name: 'jQuery', category: 'JS library', script: [/jquery[.-]?([\d.]+)?(\.min)?\.js/i], version: /jquery[.-]([\d]+\.[\d.]+)(?:\.min)?\.js/i },
    { name: 'Bootstrap', category: 'UI framework', html: [/bootstrap(\.min)?\.css/i], script: [/bootstrap(\.bundle)?(\.min)?\.js/i], version: /bootstrap[@/-]([\d]+\.[\d.]+)/i },
    { name: 'Tailwind CSS', category: 'UI framework', html: [/cdn\.tailwindcss\.com/i, /tailwind/i] },
    { name: 'Alpine.js', category: 'JS framework', html: [/\bx-data=/], script: [/alpinejs/i] },
    { name: 'htmx', category: 'JS library', html: [/\bhx-(get|post)=/], script: [/htmx(\.min)?\.js/i] },
    // Analytics / marketing
    { name: 'Google Analytics', category: 'Analytics', html: [/google-analytics\.com\/(analytics|ga)\.js/i, /gtag\(['"]config['"],\s*['"](G|UA)-/i], script: [/googletagmanager\.com\/gtag\/js/i] },
    { name: 'Google Tag Manager', category: 'Tag manager', html: [/googletagmanager\.com\/gtm\.js/i, /GTM-[A-Z0-9]{4,}/] },
    { name: 'Meta Pixel', category: 'Analytics', html: [/connect\.facebook\.net\/[^"']+\/fbevents\.js/i, /fbq\(['"]init/] },
    { name: 'Hotjar', category: 'Analytics', html: [/static\.hotjar\.com/i, /hjSettings/] },
    { name: 'Plausible', category: 'Analytics', script: [/plausible\.io\/js/i] },
    { name: 'Matomo', category: 'Analytics', html: [/matomo\.js|piwik\.js/i, /_paq\.push/] },
    { name: 'Microsoft Clarity', category: 'Analytics', html: [/clarity\.ms\/tag/i] },
    { name: 'Segment', category: 'Analytics', html: [/cdn\.segment\.com\/analytics\.js/i] },
    { name: 'Cloudflare Web Analytics', category: 'Analytics', html: [/static\.cloudflareinsights\.com/i] },
    { name: 'Intercom', category: 'Live chat', html: [/widget\.intercom\.io/i, /intercomSettings/] },
    { name: 'Zendesk', category: 'Live chat', html: [/static\.zdassets\.com/i] },
    { name: 'Stripe', category: 'Payments', script: [/js\.stripe\.com/i] },
    { name: 'reCAPTCHA', category: 'Security', html: [/google\.com\/recaptcha/i] },
    { name: 'hCaptcha', category: 'Security', html: [/hcaptcha\.com\/1\/api\.js/i] },
    { name: 'Cloudflare Turnstile', category: 'Security', html: [/challenges\.cloudflare\.com\/turnstile/i] },
    { name: 'OneTrust', category: 'Consent', html: [/cdn\.cookielaw\.org/i, /optanon/i] },
    { name: 'Cookiebot', category: 'Consent', html: [/consent\.cookiebot\.com/i] },
    { name: 'Google Fonts', category: 'Fonts', html: [/fonts\.googleapis\.com/i] },
    { name: 'Font Awesome', category: 'Fonts', html: [/font-?awesome/i] },
    // CDN / hosting / edge
    { name: 'Cloudflare', category: 'CDN / WAF', header: [['server', /cloudflare/i], ['cf-ray', /./]], cookie: [/^__cf_bm=|^__cflb=/] },
    { name: 'Fastly', category: 'CDN', header: [['x-served-by', /cache-/i], ['fastly-debug-digest', /./], ['x-fastly-request-id', /./]] },
    { name: 'Akamai', category: 'CDN / WAF', header: [['server', /akamai/i], ['x-akamai-transformed', /./]] },
    { name: 'Amazon CloudFront', category: 'CDN', header: [['x-amz-cf-id', /./], ['via', /cloudfront/i]] },
    { name: 'Amazon S3', category: 'Hosting', header: [['server', /AmazonS3/i]] },
    { name: 'Vercel', category: 'Hosting', header: [['server', /vercel/i], ['x-vercel-id', /./]] },
    { name: 'Netlify', category: 'Hosting', header: [['server', /netlify/i], ['x-nf-request-id', /./]] },
    { name: 'GitHub Pages', category: 'Hosting', header: [['server', /github\.com/i]] },
    { name: 'Heroku', category: 'Hosting', header: [['via', /vegur/i]] },
    { name: 'Google Cloud', category: 'Hosting', header: [['server', /^(gws|Google Frontend|gfe)/i], ['via', /google/i]] },
    { name: 'Azure', category: 'Hosting', header: [['x-azure-ref', /./], ['x-ms-request-id', /./]] },
    { name: 'Sucuri', category: 'WAF', header: [['x-sucuri-id', /./], ['server', /sucuri/i]] },
    { name: 'Imperva', category: 'WAF', header: [['x-iinfo', /./]], cookie: [/^incap_ses_|^visid_incap_/] },
    { name: 'Varnish', category: 'Cache', header: [['x-varnish', /./], ['via', /varnish/i]] },
    // Servers / languages
    { name: 'Nginx', category: 'Web server', header: [['server', /nginx/i]], version: /nginx\/([\d.]+)/i },
    { name: 'Apache', category: 'Web server', header: [['server', /apache/i]], version: /Apache\/([\d.]+)/i },
    { name: 'Microsoft IIS', category: 'Web server', header: [['server', /IIS/i]], version: /IIS\/([\d.]+)/i },
    { name: 'LiteSpeed', category: 'Web server', header: [['server', /litespeed/i]] },
    { name: 'Caddy', category: 'Web server', header: [['server', /caddy/i]] },
    { name: 'Envoy', category: 'Proxy', header: [['server', /envoy/i], ['x-envoy-upstream-service-time', /./]] },
    { name: 'PHP', category: 'Language', header: [['x-powered-by', /php/i]], cookie: [/^PHPSESSID=/], version: /PHP\/([\d.]+)/i },
    { name: 'ASP.NET', category: 'Framework', header: [['x-powered-by', /asp\.net/i], ['x-aspnet-version', /./]], cookie: [/^ASP\.NET_SessionId=/], html: [/__VIEWSTATE/] },
    { name: 'Express', category: 'Framework', header: [['x-powered-by', /express/i]] },
    { name: 'Java (Servlet)', category: 'Language', cookie: [/^JSESSIONID=/] },
    { name: 'Laravel', category: 'Framework', cookie: [/^laravel_session=/] },
    { name: 'Django', category: 'Framework', cookie: [/^csrftoken=/], html: [/csrfmiddlewaretoken/] },
    { name: 'Ruby on Rails', category: 'Framework', html: [/csrf-param" content="authenticity_token/], cookie: [/^_[a-z_]+_session=/] },
];

export function fingerprint(html: string, headers: Headers, setCookies: string[], scripts: string[], generator: string): TechHit[] {
    const hits = new Map<string, TechHit>();
    const sample = html.length > 600000 ? html.slice(0, 600000) : html;

    for (const s of SIGS) {
        let evidence = '';
        if (!evidence && s.meta && generator && s.meta.test(generator)) evidence = `meta generator: ${generator}`;
        if (!evidence && s.header) for (const [h, r] of s.header) { const v = headers.get(h); if (v && r.test(v)) { evidence = `header ${h}: ${v.slice(0, 60)}`; break; } }
        if (!evidence && s.cookie) for (const r of s.cookie) { const c = setCookies.find(x => r.test(x)); if (c) { evidence = `cookie ${c.split('=')[0]}`; break; } }
        if (!evidence && s.script) for (const r of s.script) { const m = scripts.find(x => r.test(x)); if (m) { evidence = `script ${m.slice(0, 80)}`; break; } }
        if (!evidence && s.html) for (const r of s.html) { const m = sample.match(r); if (m) { evidence = `html "${m[0].slice(0, 50)}"`; break; } }
        if (!evidence) continue;
        hits.set(s.name, { name: s.name, category: s.category, evidence, confidence: /^(meta|header|script)/.test(evidence) ? 'high' : 'medium' });
    }
    enrichVersions(hits, sample, headers, scripts, generator);
    if (hits.has('Tailwind CSS') && !/cdn\.tailwindcss\.com|tailwind(\.min)?\.css|--tw-/.test(sample)) hits.delete('Tailwind CSS');
    return [...hits.values()].sort((a, b) => a.category.localeCompare(b.category));
}

// Versions come from product-specific fields, never unrelated text or a generic ?ver=.
function enrichVersions(hits: Map<string, TechHit>, html: string, headers: Headers, scripts: string[], generator: string) {
    const $ = cheerio.load(html);
    const resources = [...scripts, ...$('script[src]').map((_, e) => $(e).attr('src') || '').get(), ...$('link[href]').map((_, e) => $(e).attr('href') || '').get()];
    const candidates = new Map<string, { version: string; source: string }[]>();
    const record = (name: string, category: string, version: string | undefined, source: string) => {
        if (!hits.has(name)) hits.set(name, { name, category, evidence: source, confidence: 'medium' });
        if (!version || !/^\d{1,9}\.\d{1,9}(?:\.\d{1,9})?$/.test(version)) return;
        const list = candidates.get(name) || [];
        list.push({ version, source }); candidates.set(name, list);
    };
    const metaProducts: [string, string][] = [['WordPress', 'CMS'], ['Drupal', 'CMS'], ['Joomla', 'CMS'], ['Ghost', 'CMS'], ['Astro', 'JS framework'], ['WooCommerce', 'E-commerce']];
    for (const [name, category] of metaProducts) {
        const m = generator.match(new RegExp('^' + name + '[ /]+(\\d+\\.\\d+(?:\\.\\d+)?)(?:$|[ ;])', 'i'));
        if (m) record(name, category, m[1], `meta generator: ${generator.slice(0, 160)}`);
    }
    const headerProducts: [string, string, string, RegExp][] = [
        ['PHP', 'Language', 'x-powered-by', /\bPHP\/(\d+\.\d+\.\d+)(?=$|[ ;,])/i],
        ['Apache', 'Web server', 'server', /\bApache\/(\d+\.\d+\.\d+)(?=$|[ ;(])/i],
        ['Nginx', 'Web server', 'server', /\bnginx\/(\d+\.\d+\.\d+)(?=$|[ ;(])/i],
        ['Microsoft IIS', 'Web server', 'server', /\bIIS\/(\d+\.\d+)(?=$|[ ;(])/i],
        ['Drupal', 'CMS', 'x-generator', /^Drupal (\d+\.\d+(?:\.\d+)?)/i],
        ['ASP.NET', 'Framework', 'x-aspnet-version', /^(\d+\.\d+(?:\.\d+)?)/],
    ];
    for (const [name, category, header, re] of headerProducts) {
        const value = headers.get(header) || ''; const m = value.match(re);
        if (m) record(name, category, m[1], `header ${header}: ${value.slice(0, 160)}`);
    }
    const angular = $('[ng-version]').first().attr('ng-version');
    if (angular) record('Angular', 'JS framework', angular, `ng-version attribute: ${angular}`);
    for (const resource of resources.slice(0, 500)) {
        let u: URL; try { u = new URL(resource, 'https://relative.invalid'); } catch { continue; }
        const path = u.pathname;
        const products: [string, string, RegExp][] = [
            ['jQuery', 'JS library', /(?:^|\/)jquery(?:@|[-/])(\d+\.\d+\.\d+)(?!\.\d|-[a-z0-9])(?=[/.]|$)/i],
            ['Bootstrap', 'UI framework', /(?:^|\/)bootstrap(?:@|[-/])(\d+\.\d+\.\d+)(?!\.\d|-[a-z0-9])(?=[/.]|$)/i],
            ['Vue.js', 'JS framework', /(?:^|\/)vue(?:@|[-/])(\d+\.\d+\.\d+)(?!\.\d|-[a-z0-9])(?=[/.]|$)/i],
            ['React', 'JS library', /(?:^|\/)react(?:-dom)?(?:@|[-/])(\d+\.\d+\.\d+)(?!\.\d|-[a-z0-9])(?=[/.]|$)/i],
            ['Lodash', 'JS library', /(?:^|\/)lodash(?:@|[-/])(\d+\.\d+\.\d+)(?!\.\d|-[a-z0-9])(?=[/.]|$)/i],
        ];
        for (const [name, category, re] of products) {
            const m = path.match(re);
            if (m) record(name, category, m[1], `asset URL: ${resource.slice(0, 240)}`);
        }
        // WordPress asset query values describe that asset, not WordPress core.
        const wp = path.match(/\/wp-content\/(plugins|themes)\/([a-z0-9_-]{1,80})\//i);
        if (wp) {
            const name = `WordPress ${wp[1] === 'plugins' ? 'plugin' : 'theme'}: ${wp[2]}`;
            record(name, wp[1] === 'plugins' ? 'WordPress plugin' : 'WordPress theme', undefined, `asset path: ${path.slice(0, 200)}`);
            const hint = u.searchParams.get('ver') || u.searchParams.get('version');
            if (hint && /^\d{1,9}\.\d{1,9}(?:\.\d{1,9})?$/.test(hint)) {
                const hit = hits.get(name)!;
                hit.versionHints = [...new Set([...(hit.versionHints || []), hint])].slice(0, 5);
            }
        }
        if (/\/(?:jquery|bootstrap)(?:\.bundle)?(?:\.min)?\.(?:js|css)$/i.test(path)) {
            const name = /jquery/i.test(path) ? 'jQuery' : 'Bootstrap';
            const version = u.searchParams.get('ver') || u.searchParams.get('version');
            if (version) record(name, name === 'jQuery' ? 'JS library' : 'UI framework', version, `asset version parameter (publisher claim): ${resource.slice(0, 240)}`);
        }
    }
    for (const [name, rows] of candidates) {
        const hit = hits.get(name)!; const versions = [...new Set(rows.map(r => r.version))];
        hit.versionCandidates = versions; hit.versionEvidence = rows.map(r => `${r.version} — ${r.source}`).join(' | ').slice(0, 1500);
        hit.version = versions.length === 1 ? versions[0] : undefined;
        if (versions.length > 1) hit.confidence = 'low';
    }
}

/** Inspect only linked static assets. Never execute downloaded JavaScript. */
export function mergeAssetVersions(hits: TechHit[], text: string, source: string): TechHit[] {
    const signatures: [string, string, RegExp][] = [
        ['jQuery', 'JS library', /(?:jQuery JavaScript Library v|jQuery v)(\d+\.\d+\.\d+)(?![\d.]|-[a-z0-9])/i],
        ['Bootstrap', 'UI framework', /Bootstrap v(\d+\.\d+\.\d+)(?![\d.]|-[a-z0-9])/i],
        ['Vue.js', 'JS framework', /Vue\.js v(\d+\.\d+\.\d+)(?![\d.]|-[a-z0-9])/i],
        ['React', 'JS library', /@license React v(\d+\.\d+\.\d+)(?![\d.]|-[a-z0-9])/i],
        ['Lodash', 'JS library', /Lodash <https:\/\/lodash\.com\/>[\s\S]{0,120}?VERSION = ['"](\d+\.\d+\.\d+)['"]/],
    ];
    const result = hits.map(h => ({ ...h }));
    for (const [name, category, re] of signatures) {
        const m = text.slice(0, 128 * 1024).match(re); if (!m) continue;
        let hit = result.find(h => h.name === name);
        if (!hit) { hit = { name, category, evidence: `linked asset: ${source}`, confidence: 'medium' }; result.push(hit); }
        const versions = [...new Set([...(hit.versionCandidates || (hit.version ? [hit.version] : [])), m[1]])];
        hit.versionCandidates = versions; hit.version = versions.length === 1 ? versions[0] : undefined;
        hit.versionEvidence = [hit.versionEvidence, `asset banner: ${m[0].slice(0, 160)} — ${source}`].filter(Boolean).join(' | ').slice(0, 1500);
        if (versions.length > 1) hit.confidence = 'low';
    }
    return result;
}
