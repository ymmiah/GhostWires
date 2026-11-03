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
    error?: string;
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
    assessment?: SurfaceAssessment; // optional for backwards-compatible report imports
    workspaceReceipt?: string; // short-lived, session-bound permission to save an owner assessment
}

export type AssessmentMode = 'public' | 'owner';
export type FindingConfidence = 'high' | 'medium' | 'low';
export interface SurfaceFinding {
    id: string;
    checkId: string;
    title: string;
    severity: Severity;
    confidence: FindingConfidence;
    status: 'observed-exposure' | 'potential-vulnerability';
    asset: string;
    observedAt: string;
    evidence: string[];
    impact: string;
    remediation: string;
    verification: string;
    limitations: string[];
    references: string[];
    advisory?: { id: string; cve?: string; affectedRange: string; fixedVersion?: string; knownExploited: boolean | null; kev?: { dateAdded: string; requiredAction: string; ransomwareUse: string } };
}
export interface AssessmentCoverage {
    checkId: string;
    label: string;
    status: 'completed' | 'partial' | 'not-assessed' | 'blocked' | 'error';
    detail: string;
}
export interface ObservedComponent {
    name: string;
    version?: string;
    source: string;
    confidence: FindingConfidence;
}
export interface SurfaceAssessment {
    schemaVersion: '1.0';
    mode: AssessmentMode;
    generatedAt: string;
    scope: string;
    findings: SurfaceFinding[];
    components: ObservedComponent[];
    coverage: AssessmentCoverage[];
    limitations: string[];
    intelligence: { source: string; retrievedAt?: string; status: 'not-requested' | 'current' | 'partial' | 'unavailable'; detail: string };
    threatIntelligence?: { source: string; status: 'not-requested' | 'current' | 'stale' | 'unavailable'; retrievedAt?: string; catalogVersion?: string; detail: string };
    groups?: { id: string; title: string; reason: string; findingIds: string[] }[];
}
export interface OwnershipChallenge {
    origin: string;
    recordName: string;
    recordValue: string;
    token: string;
    expiresAt: string;
}
export interface InventoryPackage { name: string; version: string; }

export type WorkspaceRole = 'owner' | 'analyst' | 'viewer';
export type ReviewState = 'open' | 'in-review' | 'resolved' | 'accepted-risk';
export interface WorkspaceSession {
    enabled: boolean;
    user?: { email: string; role: WorkspaceRole; workspace: string };
    csrfToken?: string;
    retentionDays?: number;
}
export interface InvestigationSummary {
    id: string; scope: string; title: string; state: ReviewState;
    createdAt: string; updatedAt: string; expiresAt: string; findingCount: number; kevCount: number;
    version: number;
}
export interface Investigation extends InvestigationSummary {
    assessment: SurfaceAssessment;
    timeline: { sequence: number; at: string; actor: string; action: 'saved' | 'reviewed' | 'note'; detail: string }[];
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
    findingGuidance?: { findingId: string; explanation: string; recommendation: string }[];
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
