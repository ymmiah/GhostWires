export interface ExtractedImage {
    src: string;
    alt: string;
    detailedDescription?: string;
}

export interface ExtractedLink {
    href: string;
    text: string;
    type: 'internal' | 'external' | 'social';
}

export interface Technology {
    name: string;
    version: string;
}

export interface Vulnerability {
    cve: string;
    description: string;
    severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
}

export interface DNSResult {
    a: string[];
    mx: string[];
}

export interface WHOISResult {
    registrar: string;
    creationDate: string;
}

export interface AccessibilityIssue {
    impact: 'critical' | 'serious' | 'moderate' | 'minor';
    description: string;
    element: string;
}

export interface CMSTheme {
    name: string;
    version?: string;
}

export interface CMSPlugin {
    name: string;
    version?: string;
}

export interface ServerLocation {
    city: string;
    region: string;
    country: string;
}

export interface SecurityHeader {
    name: string;
    value: string;
}

export interface AdvancedReconResult {
    owner: string;
    hostingPlatform: string;
    serverIP: string;
    serverLocation?: ServerLocation;
    platform: string;
    waf?: string;
    threatIntel?: string;
    cmsTheme?: CMSTheme;
    cmsPlugins?: CMSPlugin[];
    technologies: Technology[];
    vulnerabilities?: Vulnerability[];
    dnsRecords?: DNSResult;
    whois?: WHOISResult;
    securityHeaders?: SecurityHeader[];
}

export interface Person {
    name: string;
    title: string;
}

export interface SocialLinks {
    twitter?: string;
    linkedin?: string;
    github?: string;
    facebook?: string;
}

export interface OSINTResult {
    emails: string[];
    phoneNumbers: string[];
    addresses: string[];
    peopleLinked: Person[];
    socialLinks?: SocialLinks;
}

export interface SocialMeta {
    ogTitle?: string;
    ogDescription?: string;
    ogImage?: string;
    twitterCard?: string;
}

export interface SEOPerformanceResult {
    titleTag?: string;
    h1Tags?: string[];
    wordCount?: number;
    performanceHints?: string[];
    socialMeta?: SocialMeta;
}

export interface ContentLanguageResult {
    sentiment: number; // Score from -1 (negative) to 1 (positive)
    readabilityScore: string; // e.g., "College graduate level"
    detectedLanguage: string; // e.g., "English (en)"
    keyTopics: string[]; // Array of key topics/entities
}

export interface PageContent {
    url: string;
    title: string;
    summary: string;
}

export interface ExtractionResult {
    summary: string;
    mainContent: string;
    metaDescription: string;
    metaKeywords: string[];
    images: ExtractedImage[];
    links: ExtractedLink[];
    subdomains: string[];
    subfolders: string[];
    advancedRecon: AdvancedReconResult;
    osint: OSINTResult;
    accessibilityScore?: number;
    accessibilityIssues?: AccessibilityIssue[];
    seoPerformance?: SEOPerformanceResult;
    contentLanguage?: ContentLanguageResult;
}

export interface ChatMessage {
    role: 'user' | 'model';
    content: string;
}
