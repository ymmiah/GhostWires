import type { SurfaceFinding, TechHit, TechnologyAdvisoryCheck, Severity } from '../../types';
import { safeFetch, TargetError } from '../net';

// Explicit product identities prevent keyword matches being reported as vulnerabilities.
const PRODUCTS: Record<string, [string, string]> = {
    PHP: ['php', 'php'], WordPress: ['wordpress', 'wordpress'], Drupal: ['drupal', 'drupal'],
    Apache: ['apache', 'http_server'], Nginx: ['nginx', 'nginx'], jQuery: ['jquery', 'jquery'],
    Bootstrap: ['getbootstrap', 'bootstrap'], 'Next.js': ['vercel', 'next.js'],
    'Vue.js': ['vuejs', 'vue'], React: ['facebook', 'react'], Lodash: ['lodash', 'lodash'],
};
const exact = (v: unknown): v is string => typeof v === 'string' && /^\d{1,9}\.\d{1,9}\.\d{1,9}$/.test(v);
const compare = (a: string, b: string) => {
    const x = a.split('.').map(Number), y = b.split('.').map(Number);
    for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
    return 0;
};

/** A matching affected product is a candidate, not proof all environment conditions hold. */
export function affectedProduct(configurations: unknown, vendor: string, product: string, version: string): boolean {
    if (!exact(version) || !Array.isArray(configurations)) return false;
    const visit = (node: any, depth: number): boolean => {
        if (!node || depth > 12 || node.negate === true) return false;
        if (Array.isArray(node.cpeMatch)) for (const m of node.cpeMatch) {
            if (m?.vulnerable !== true || typeof m.criteria !== 'string') continue;
            const c = m.criteria.split(':');
            if (c.length !== 13 || c[0] !== 'cpe' || c[1] !== '2.3' || c[2] !== 'a' || c[3] !== vendor || c[4] !== product) continue;
            if (c[5] !== '*' && c[5] !== version) continue;
            // A version with update/edition constraints cannot be established from a banner.
            if (c.slice(6).some((v: string) => v !== '*' && v !== '-')) continue;
            let bounded = c[5] === version, match = true;
            for (const [key, sign, inclusive] of [
                ['versionStartIncluding', 1, true], ['versionStartExcluding', 1, false],
                ['versionEndIncluding', -1, true], ['versionEndExcluding', -1, false],
            ] as const) {
                if (m[key] === undefined) continue;
                bounded = true;
                if (!exact(m[key])) { match = false; break; }
                const d = compare(version, m[key]) * sign;
                if (d < 0 || (!inclusive && d === 0)) match = false;
            }
            if (match && bounded) return true;
        }
        return ['nodes', 'children'].some(k => Array.isArray(node[k]) && node[k].some((n: unknown) => visit(n, depth + 1)));
    };
    return configurations.some(n => visit(n, 0));
}

interface Snapshot { at: number; rows: any[]; partial: boolean; }
export class TechnologyAdvisoryClient {
    private cache = new Map<string, Snapshot>();
    private pending = new Map<string, Promise<Snapshot>>();
    private retryAt = 0;
    private nextRequestAt = 0;
    private queue: Promise<unknown> = Promise.resolve();
    constructor(private fetcher = safeFetch, private clock = Date.now, private pause = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms))) {}
    private load(cpe: string): Promise<Snapshot> {
        const cached = this.cache.get(cpe);
        if (cached && this.clock() - cached.at < 60 * 60_000) return Promise.resolve(cached);
        const pending = this.pending.get(cpe); if (pending) return pending;
        if (this.pending.size >= 3) return Promise.reject(new Error('Advisory lookup capacity reached'));
        const request = this.queue.catch(() => {}).then(async () => {
            if (this.clock() < this.retryAt) throw new Error('Feed cooling down');
            await this.pause(Math.max(0, this.nextRequestAt - this.clock()));
            this.nextRequestAt = this.clock() + 6100;
            try {
                const url = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
                url.search = new URLSearchParams({ cpeName: cpe, isVulnerable: '', noRejected: '', resultsPerPage: '100' }).toString();
                const res = await this.fetcher(url, { timeoutMs: 6000, maxBytes: 2 * 1024 * 1024, maxRedirects: 0, accept: 'application/json' });
                if (res.status !== 200 || res.truncated) throw new Error('Feed unavailable');
                const data = JSON.parse(res.text);
                if (!Array.isArray(data.vulnerabilities) || data.vulnerabilities.length > 100 || !Number.isInteger(data.totalResults) || data.totalResults < data.vulnerabilities.length || data.startIndex !== 0) throw new Error('Invalid NVD response');
                const snapshot = { at: this.clock(), rows: data.vulnerabilities, partial: data.totalResults > data.vulnerabilities.length };
                if (this.cache.size >= 100) this.cache.delete(this.cache.keys().next().value!);
                this.cache.set(cpe, snapshot); return snapshot;
            } catch (e) { this.retryAt = this.clock() + 60_000; throw e; }
        });
        this.pending.set(cpe, request); this.queue = request;
        void request.finally(() => this.pending.delete(cpe)).catch(() => {});
        return request;
    }
    async assess(tech: TechHit[], asset: string, now: string, signal?: AbortSignal): Promise<{ checks: TechnologyAdvisoryCheck[]; findings: SurfaceFinding[] }> {
        const checks: TechnologyAdvisoryCheck[] = [], findings: SurfaceFinding[] = [];
        let queried = 0;
        const priority = ['PHP', 'WordPress', 'Apache', 'Nginx', 'Drupal'];
        const ordered = tech.slice(0, 100).sort((a, b) => (priority.includes(a.name) ? priority.indexOf(a.name) : 99) - (priority.includes(b.name) ? priority.indexOf(b.name) : 99));
        for (const hit of ordered) {
            if (signal?.aborted) throw new TargetError('Assessment cancelled.', 499);
            const identity = PRODUCTS[hit.name];
            const check: TechnologyAdvisoryCheck = {
                technology: hit.name, version: hit.version, status: 'unsupported', findingIds: [],
                detail: 'No automatic advisory mapping for this product. Use the research link to investigate.',
                searchUrl: 'https://nvd.nist.gov/vuln/search/results?' + new URLSearchParams({ query: `${hit.name}${hit.version ? ' ' + hit.version : ''}`, search_type: 'all', isCpeNameSearch: 'false' }),
            };
            checks.push(check);
            if ((hit.versionCandidates?.length || 0) > 1) { check.status = 'conflicting-version'; check.detail = 'Multiple version claims observed; automatic CVE matching skipped.'; continue; }
            if (!identity) continue;
            if (!exact(hit.version)) { check.status = 'unknown-version'; check.detail = 'An exact stable x.y.z version was not observed. Product research is available; no CVE claim is made.'; continue; }
            if (queried++ >= 3) { check.status = 'partial'; check.detail = 'Three-product lookup budget reached. Follow the research link or supply an owner inventory.'; continue; }
            const [vendor, product] = identity;
            const cpe = `cpe:2.3:a:${vendor}:${product}:${hit.version}:*:*:*:*:*:*:*`;
            try {
                const snapshot = await this.load(cpe);
                if (signal?.aborted) throw new TargetError('Assessment cancelled.', 499);
                check.retrievedAt = new Date(snapshot.at).toISOString();
                let incomplete = snapshot.partial;
                for (const row of snapshot.rows) {
                    const cve = row?.cve;
                    if (!cve || !/^CVE-\d{4}-\d{4,}$/.test(cve.id) || (!Array.isArray(cve.configurations) || !cve.configurations.length)) { incomplete = true; continue; }
                    if (cve.vulnStatus === 'Rejected' || !affectedProduct(cve.configurations, vendor, product, hit.version)) continue;
                    const metrics = cve.metrics;
                    const metric = metrics?.cvssMetricV31?.[0] || metrics?.cvssMetricV30?.[0];
                    const score = metric?.cvssData?.baseScore;
                    const severity: Severity = typeof score === 'number' && score >= 0 && score <= 10 ? score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low' : 'info';
                    const summary = cve.descriptions?.find((d: any) => d?.lang === 'en' && typeof d.value === 'string')?.value?.slice(0, 1500) || 'Review the NVD record and vendor advisory.';
                    const id = `technology-${vendor}-${product}-${hit.version}-${cve.id}`;
                    if (check.findingIds.includes(id)) continue;
                    check.findingIds.push(id);
                    findings.push({
                        id, checkId: 'technology-cve', title: `${hit.name} ${hit.version}: ${cve.id}`, severity,
                        confidence: 'medium', status: 'potential-vulnerability', asset, observedAt: now,
                        evidence: [hit.evidence, hit.versionEvidence || `Observed version: ${hit.version}`, `NVD affected-product match: ${cpe}`, summary],
                        impact: 'The publicly claimed product version matches an affected NVD product/version entry. Runtime exposure and exploitability require owner verification.',
                        remediation: 'Check the vendor advisory, confirm the installed build and configuration, and apply the relevant supported security update.',
                        verification: 'Verify the installed version, distribution backports and advisory prerequisites with the site owner; repeat the assessment after updating.',
                        limitations: ['Banners and asset URLs are publisher claims and may be stale, forged or belong to unused assets.', 'NVD environment, operating-system and configuration prerequisites have not been verified. This is not a confirmed exploitable vulnerability.', 'Distribution security backports may fix a CVE without changing the upstream version.', 'Known-exploitation status has not been checked.'],
                        references: [`https://nvd.nist.gov/vuln/detail/${cve.id}`],
                        advisory: { id: cve.id, cve: cve.id, affectedRange: 'NVD affected-product entry; see linked record for complete constraints', knownExploited: null },
                    });
                }
                check.status = incomplete ? 'partial' : check.findingIds.length ? 'matched' : 'no-match';
                check.detail = `${check.findingIds.length} affected-version candidates in ${snapshot.rows.length} returned records. ${incomplete ? 'Feed coverage is incomplete.' : 'No match is not a clean bill of health.'}`;
            } catch (e) {
                if (signal?.aborted) throw new TargetError('Assessment cancelled.', 499);
                check.status = 'unavailable'; check.detail = 'NVD lookup failed, was rate-limited or returned incomplete data. Vulnerability status is unknown; use the research link.';
            }
        }
        return { checks, findings };
    }
}
export const technologyAdvisoryClient = new TechnologyAdvisoryClient();
