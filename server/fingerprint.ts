// GhostWires Mk.IV — deterministic technology fingerprinting from HTML + headers + cookies
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
    const headerBlob = [...headers.entries()].map(([k, v]) => `${k}: ${v}`).join('\n');
    const scriptBlob = scripts.join('\n');
    const sample = html.length > 600000 ? html.slice(0, 600000) : html;

    for (const s of SIGS) {
        let evidence = '';
        if (!evidence && s.meta && generator && s.meta.test(generator)) evidence = `meta generator: ${generator}`;
        if (!evidence && s.header) for (const [h, r] of s.header) { const v = headers.get(h); if (v && r.test(v)) { evidence = `header ${h}: ${v.slice(0, 60)}`; break; } }
        if (!evidence && s.cookie) for (const r of s.cookie) { const c = setCookies.find(x => r.test(x)); if (c) { evidence = `cookie ${c.split('=')[0]}`; break; } }
        if (!evidence && s.script) for (const r of s.script) { const m = scripts.find(x => r.test(x)); if (m) { evidence = `script ${m.slice(0, 80)}`; break; } }
        if (!evidence && s.html) for (const r of s.html) { const m = sample.match(r); if (m) { evidence = `html "${m[0].slice(0, 50)}"`; break; } }
        if (!evidence) continue;
        let version: string | undefined;
        if (s.version) {
            const m = (generator + '\n' + headerBlob + '\n' + scriptBlob + '\n' + sample).match(s.version);
            if (m?.[1]) version = m[1];
        }
        hits.set(s.name, { name: s.name, category: s.category, version, evidence });
    }
    if (hits.has('WooCommerce')) hits.delete('Shopify');
    if (hits.has('Tailwind CSS') && !/cdn\.tailwindcss\.com|tailwind(\.min)?\.css|--tw-/.test(sample)) hits.delete('Tailwind CSS');
    return [...hits.values()].sort((a, b) => a.category.localeCompare(b.category));
}
