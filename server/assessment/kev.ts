import type { SurfaceAssessment } from '../../types';
import { safeFetch } from '../net';

const SOURCES = [
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json',
] as const;
interface KevEntry { cveID: string; dateAdded: string; requiredAction: string; knownRansomwareCampaignUse: string; }
interface Snapshot { fetchedAt: number; releasedAt: number; version: string; entries: Map<string, KevEntry>; }
const TTL = 60 * 60_000;
const MAX_STALE = 7 * 86400_000;

export class KevClient {
    private snapshot?: Snapshot;
    private pending?: Promise<Snapshot | undefined>;
    private retryAt = 0;
    constructor(private fetcher = safeFetch, private clock = Date.now) {}

    private async refresh(): Promise<Snapshot | undefined> {
        for (const source of SOURCES) {
            try {
                const res = await this.fetcher(source, { timeoutMs: 6000, maxBytes: 8 * 1024 * 1024, maxRedirects: 0, accept: 'application/json' });
                if (res.status !== 200 || res.truncated) continue;
                const data = JSON.parse(res.text);
                const release = Date.parse(data.dateReleased);
                if (!Array.isArray(data.vulnerabilities) || data.vulnerabilities.length === 0 || data.vulnerabilities.length > 30000 || data.count !== data.vulnerabilities.length || typeof data.catalogVersion !== 'string' || !Number.isFinite(release) || release > this.clock() + 86400_000) continue;
                const entries = new Map<string, KevEntry>();
                for (const entry of data.vulnerabilities) {
                    if (!entry || !/^CVE-\d{4}-\d{4,}$/.test(entry.cveID) || typeof entry.requiredAction !== 'string' || typeof entry.dateAdded !== 'string' || !Number.isFinite(Date.parse(entry.dateAdded))) throw new Error('Invalid KEV entry');
                    entries.set(entry.cveID, { cveID: entry.cveID, dateAdded: entry.dateAdded, requiredAction: entry.requiredAction.slice(0, 2000), knownRansomwareCampaignUse: String(entry.knownRansomwareCampaignUse || 'Unknown').slice(0, 30) });
                }
                if (entries.size !== data.count) continue;
                this.snapshot = { fetchedAt: this.clock(), releasedAt: release, version: data.catalogVersion.slice(0, 50), entries };
                this.retryAt = 0;
                return this.snapshot;
            } catch { /* Try only the official mirror, never arbitrary URLs supplied by a report. */ }
        }
        this.retryAt = this.clock() + 5 * 60_000;
        return this.snapshot;
    }

    async enrich(assessment: SurfaceAssessment): Promise<void> {
        const matched = assessment.findings.filter(f => /^CVE-\d{4}-\d{4,}$/.test(f.advisory?.cve || ''));
        const info: NonNullable<SurfaceAssessment['threatIntelligence']> = { source: 'CISA Known Exploited Vulnerabilities', status: 'not-requested', detail: 'No matched CVE IDs to enrich. KEV does not discover vulnerabilities or prove compromise.' };
        assessment.threatIntelligence = info;
        if (!matched.length) return;
        const now = this.clock();
        const expired = !this.snapshot || now - this.snapshot.fetchedAt >= TTL;
        let refreshed = !expired;
        if (expired && now >= this.retryAt) {
            if (!this.pending) this.pending = this.refresh().finally(() => { this.pending = undefined; });
            const previous = this.snapshot?.fetchedAt;
            await this.pending;
            refreshed = this.snapshot?.fetchedAt !== previous && !!this.snapshot;
        }
        const snapshot = this.snapshot;
        const usable = snapshot && now - snapshot.fetchedAt <= MAX_STALE;
        const current = usable && refreshed && now - snapshot.releasedAt <= MAX_STALE;
        info.status = !usable ? 'unavailable' : current ? 'current' : 'stale';
        if (snapshot) { info.retrievedAt = new Date(snapshot.fetchedAt).toISOString(); info.catalogVersion = snapshot.version; }
        info.detail = current ? 'Exact CVE matches only. A listing establishes known exploitation elsewhere; absence is not proof that a CVE has never been exploited.' : usable ? 'Cached catalogue is stale or the last refresh failed. A missing CVE remains unknown.' : 'Official catalogue and mirror were unavailable or invalid. Exploitation status remains unknown.';
        for (const f of matched) {
            const entry = usable ? snapshot.entries.get(f.advisory!.cve!) : undefined;
            f.advisory!.knownExploited = entry ? true : current ? false : null;
            delete f.advisory!.kev;
            if (entry) {
                f.advisory!.kev = { dateAdded: entry.dateAdded, requiredAction: entry.requiredAction, ransomwareUse: entry.knownRansomwareCampaignUse };
                const ref = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog';
                if (!f.references.includes(ref)) f.references.push(ref);
            }
            f.limitations = f.limitations.filter(l => l !== 'Known-exploitation status has not been checked.');
            f.limitations.push('KEV enrichment does not establish exploitation of this asset.');
        }
    }
}

export const kevClient = new KevClient();
