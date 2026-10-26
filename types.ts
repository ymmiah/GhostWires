// GhostWires Mk.IV — shared types (server + client)

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type AIProviderId = 'gemini' | 'nim' | 'openrouter' | 'groq';

export interface RedirectHop { url: string; status: number; }

export interface TargetInfo {
    input: string;
    url: string;
    finalUrl: string;
    hostname: string;
    registrableDomain: string;
    status: number;
    contentType: string;
    bytes: number;
    responseTimeMs: number;
    redirectChain: RedirectHop[];
    resolvedIPs: string[];
}

export interface DNSIntel {
    a: string[];
    aaaa: string[];
    cname: string[];
    mx: { exchange: string; priority: number }[];
    ns: string[];
    txt: string[];
    soa?: { nsname: string; hostmaster: string; serial: number } | null;
    caa: string[];
    reverse: Record<string, string[]>;
    emailSecurity: {
        spf: string | null;
        dmarc: string | null;
        dmarcPolicy: string | null;
        findings: string[];
    };
    errors: string[];
    resolver: 'system' | 'doh';
    saasFootprint: string[];
}

export interface TLSIntel {
    available: boolean;
    protocol?: string;
    cipher?: string;
    subject?: string;
    issuer?: string;
    validFrom?: string;
    validTo?: string;
    daysRemaining?: number;
    sans: string[];
    fingerprint256?: string;
    serialNumber?: string;
    authorized?: boolean;
    authorizationError?: string;
    error?: string;
}

export interface HeaderFinding {
    header: string;
    present: boolean;
    value?: string;
    severity: Severity;
    note: string;
}

export interface HeadersAudit {
    score: number; // 0-100
    grade: string; // A+..F
    findings: HeaderFinding[];
    disclosure: { header: string; value: string }[];
    cookies: { name: string; secure: boolean; httpOnly: boolean; sameSite: string | null }[];
    raw: Record<string, string>;
}

export interface TechHit {
    name: string;
    category: string;
    version?: string;
    evidence: string;
}

export interface ContactIntel {
    emails: string[];
    phones: string[];
    socials: { platform: string; url: string }[];
    addresses: string[];
}

export interface PageMeta {
    title: string;
    description: string;
    keywords: string[];
    lang: string;
    canonical: string;
    generator: string;
    robotsMeta: string;
    og: Record<string, string>;
    twitter: Record<string, string>;
    headings: { h1: string[]; h2: string[] };
    wordCount: number;
    textSample: string;
    jsonLdTypes: string[];
}

export interface ExtractedLink { href: string; text: string; type: 'internal' | 'external' | 'social'; }
export interface ExtractedImage { src: string; alt: string; detailedDescription?: string; }

export interface A11yIssue { impact: 'critical' | 'serious' | 'moderate' | 'minor'; description: string; count: number; }
export interface A11yAudit { score: number; issues: A11yIssue[]; }

export interface RobotsIntel {
    found: boolean;
    disallow: string[];
    allow: string[];
    sitemaps: string[];
    crawlDelay?: number;
    raw?: string;
}

export interface SitemapIntel {
    found: boolean;
    source?: string;
    urlCount: number;
    sample: string[];
    nestedSitemaps: string[];
}

export interface SecurityTxt { found: boolean; url?: string; contact: string[]; policy: string[]; expires?: string; }

export interface CTIntel { enabled: boolean; subdomains: string[]; certCount: number; error?: string; }

export interface WaybackIntel {
    enabled: boolean;
    available: boolean;
    closestUrl?: string;
    closestTimestamp?: string;
    firstSeen?: string;
    snapshotCount?: number;
    error?: string;
}

export interface ReconReport {
    engine: string;
    generatedAt: string;
    durationMs: number;
    target: TargetInfo;
    dns: DNSIntel;
    tls: TLSIntel;
    headers: HeadersAudit;
    tech: TechHit[];
    contacts: ContactIntel;
    meta: PageMeta;
    links: ExtractedLink[];
    images: ExtractedImage[];
    subfolders: string[];
    forms: { action: string; method: string; inputs: number; hasPassword: boolean }[];
    accessibility: A11yAudit;
    robots: RobotsIntel;
    sitemap: SitemapIntel;
    securityTxt: SecurityTxt;
    ct: CTIntel;
    wayback: WaybackIntel;
    notes: string[];
}

export interface CrawlPage {
    url: string;
    status: number;
    title: string;
    description: string;
    wordCount: number;
    depth: number;
    outLinks: number;
    emails: string[];
    error?: string;
}

export interface CrawlResult { pages: CrawlPage[]; skippedByRobots: string[]; edges: [string, string][]; }

export interface AIAnalysis {
    provider: AIProviderId;
    model: string;
    summary: string;
    sentiment: number;
    readability: string;
    language: string;
    keyTopics: string[];
    entities: string[];
    seoNarrative: string;
    a11yNarrative: string;
    securityNarrative: string;
    recommendations: string[];
}

export interface ProviderInfo {
    id: AIProviderId;
    label: string;
    model: string;
    configured: boolean;
    vision: boolean;
}

export interface ProvidersResponse { default: AIProviderId | null; byokOnly: boolean; providers: ProviderInfo[]; }

export interface ChatMessage { role: 'user' | 'model'; content: string; }
