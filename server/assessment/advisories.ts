import type { AssessmentCoverage, InventoryPackage, SurfaceAssessment, SurfaceFinding, Severity } from '../../types';
import { safeFetch, TargetError } from '../net';

export function validateInventory(input: unknown): InventoryPackage[] {
    if (input === undefined) return [];
    if (!Array.isArray(input) || input.length > 100) throw new TargetError('Inventory must contain at most 100 Composer packages.');
    const packages = input.map(p => {
        if (!p || typeof p.name !== 'string' || !/^[a-z0-9_.-]+\/[a-z0-9_.-]+$/.test(p.name) || p.name.length > 160 || typeof p.version !== 'string' || !/^v?\d{1,9}\.\d{1,9}\.\d{1,9}$/.test(p.version)) throw new TargetError('Inventory requires Composer vendor/package names and exact stable x.y.z versions.');
        return { name: p.name, version: p.version.replace(/^v/, '') };
    });
    const seen = new Map<string, string>();
    for (const p of packages) {
        if (seen.has(p.name) && seen.get(p.name) !== p.version) throw new TargetError('Conflicting versions for the same inventory package.');
        seen.set(p.name, p.version);
    }
    return [...seen].map(([name, version]) => ({ name, version }));
}

function compare(a: string, b: string): number {
    const x = a.split('.').map(Number), y = b.split('.').map(Number);
    for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
    return 0;
}

/** Conservative evaluator for GitHub's stable numeric comparator ranges; unsupported syntax stays unknown. */
export function matchesRange(version: string, range: string): boolean | null {
    if (!/^\d{1,9}\.\d{1,9}\.\d{1,9}$/.test(version) || typeof range !== 'string' || range.length > 500) return null;
    const branches = range.split('||');
    const evaluated = branches.map(branch => {
        const terms = branch.trim().split(/\s*,\s*/);
        const values = terms.map(term => {
            const m = term.trim().match(/^(<=|>=|<|>|=)?\s*(\d{1,9}\.\d{1,9}\.\d{1,9})$/);
            if (!m) return null;
            const c = compare(version, m[2]);
            return ({ '<': c < 0, '<=': c <= 0, '>': c > 0, '>=': c >= 0, '=': c === 0 })[m[1] || '='];
        });
        return values.includes(false) ? false : values.includes(null) ? null : true;
    });
    return evaluated.includes(true) ? true : evaluated.includes(null) ? null : false;
}

interface Advisory {
    ghsa_id: string; cve_id?: string; summary: string; severity: string; type: string; withdrawn_at?: string;
    vulnerabilities: { package: { ecosystem: string; name: string }; vulnerable_version_range: string; first_patched_version?: string }[];
}
const cache = new Map<string, { at: number; rows: Advisory[]; partial: boolean }>();
const CACHE_TTL = 15 * 60_000;

export async function assessAdvisories(inventory: InventoryPackage[], asset: string, now: string, fetcher = safeFetch): Promise<{ findings: SurfaceFinding[]; coverage: AssessmentCoverage; intelligence: SurfaceAssessment['intelligence'] }> {
    const base = { checkId: 'composer-advisories', label: 'Composer advisory matching' };
    if (!inventory.length) return { findings: [], coverage: { ...base, status: 'not-assessed', detail: 'No exact Composer package inventory supplied. Public technology CVE checks are listed separately.' }, intelligence: { source: 'GitHub-reviewed Composer advisories', status: 'not-requested', detail: 'Optional; only selected package names and versions are sent to GitHub.' } };
    const findings: SurfaceFinding[] = [];
    let partial = false;
    let retrieved = Date.now();
    let available = false;
    const problems = new Set<string>();
    // Five fixed-host requests maximum, sequential and capped. Never send target URL or lockfile contents.
    for (let offset = 0; offset < inventory.length; offset += 20) {
        const group = inventory.slice(offset, offset + 20);
        const query = group.map(p => `${p.name}@${p.version}`).sort().join(',');
        let entry = cache.get(query);
        if (!entry || Date.now() - entry.at >= CACHE_TTL) {
            try {
                const url = new URL('https://api.github.com/advisories');
                url.search = new URLSearchParams({ ecosystem: 'composer', affects: query, type: 'reviewed', per_page: '100' }).toString();
                const res = await fetcher(url, { timeoutMs: 8000, maxBytes: 2 * 1024 * 1024, maxRedirects: 0, accept: 'application/vnd.github+json' });
                if (res.status !== 200 || res.truncated) throw new Error(`Advisory feed HTTP ${res.status} or incomplete response`);
                const rows = JSON.parse(res.text);
                if (!Array.isArray(rows)) throw new Error('Invalid advisory feed');
                entry = { at: Date.now(), rows, partial: /rel="next"/.test(res.headers.get('link') || '') };
                if (cache.size >= 50) cache.delete(cache.keys().next().value!);
                cache.set(query, entry);
            } catch { partial = true; problems.add('A feed request failed, was rate-limited, or returned incomplete data.'); continue; }
        }
        available = true;
        retrieved = Math.min(retrieved, entry.at);
        partial ||= entry.partial;
        if (entry.partial) problems.add('The feed has additional pages; this bounded assessment uses its first page only.');
        for (const row of entry.rows) {
            if (!row || typeof row !== 'object' || !/^GHSA-[a-z0-9-]+$/.test(row.ghsa_id) || !Array.isArray(row.vulnerabilities)) { partial = true; problems.add('Some feed records were invalid and were excluded.'); continue; }
            if (row.type !== 'reviewed' || row.withdrawn_at) continue;
            for (const v of row.vulnerabilities) {
                if (v?.package?.ecosystem !== 'composer') continue;
                const p = group.find(p => p.name === v.package.name);
                if (!p) continue;
                const matched = matchesRange(p.version, v.vulnerable_version_range);
                if (matched === null) { partial = true; problems.add('Some advisory version ranges require manual review.'); continue; }
                if (!matched) continue;
                const severity: Severity = ['critical', 'high', 'medium', 'low'].includes(row.severity) ? row.severity as Severity : 'info';
                const cve = /^CVE-\d{4}-\d{4,}$/.test(row.cve_id || '') ? row.cve_id : undefined;
                findings.push({
                    id: `composer-${p.name.replace('/', '-')}-${row.ghsa_id}`, checkId: base.checkId,
                    title: `${p.name}: ${String(row.summary).slice(0, 220)}`, severity, confidence: 'medium', status: 'potential-vulnerability',
                    asset, observedAt: now, evidence: [`Owner-supplied inventory: ${p.name}@${p.version}`, `Advisory affected range: ${v.vulnerable_version_range}`],
                    impact: 'The supplied package version matches a reviewed advisory. Runtime reachability and exploit prerequisites have not been verified.',
                    remediation: v.first_patched_version ? `Review the advisory and upgrade to an appropriate supported release containing the fix (first patched version listed: ${v.first_patched_version}).` : 'Follow the linked advisory and maintainer guidance; no patched version was supplied.',
                    verification: 'Update the deployed lockfile, verify the deployed version and rerun this inventory assessment.',
                    limitations: ['Inventory is owner-supplied and may differ from the deployed application.', 'Vendor backports, enabled features and exploit prerequisites require owner review.', 'Known-exploitation status has not been checked.'],
                    references: [`https://github.com/advisories/${row.ghsa_id}`],
                    advisory: { id: row.ghsa_id, cve, affectedRange: v.vulnerable_version_range, fixedVersion: v.first_patched_version, knownExploited: null },
                });
            }
        }
    }
    const detail = [...problems, `Checked ${inventory.length} exact package versions. This feed does not cover PHP or database runtimes or all WordPress plugins.`].join(' ');
    return { findings, coverage: { ...base, status: !available ? 'error' : partial ? 'partial' : 'completed', detail }, intelligence: { source: 'GitHub-reviewed Composer advisories', retrievedAt: available ? new Date(retrieved).toISOString() : undefined, status: !available ? 'unavailable' : partial ? 'partial' : 'current', detail } };
}
