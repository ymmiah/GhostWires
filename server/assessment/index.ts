import type { AssessmentMode, InventoryPackage, SurfaceAssessment, TechHit } from '../../types';
import { politeDelay, safeFetch, TargetError, type SafeResponse } from '../net';
import { robotsAllows } from '../surfaceIntel';
import type { RobotsIntel } from '../../types';
import { detectExposures } from './detect';
import { assessAdvisories } from './advisories';
import { redactReport } from './redact';

export const OWNER_PATHS = ['/.env', '/phpinfo.php', '/phpmyadmin/', '/adminer.php', '/.git/HEAD'] as const;

export async function assessSurface(page: SafeResponse, tech: TechHit[], mode: AssessmentMode, robots: RobotsIntel, inventory: InventoryPackage[] = [], signal?: AbortSignal, fetcher = safeFetch): Promise<SurfaceAssessment> {
    const now = new Date().toISOString();
    const detected = detectExposures(page, now);
    const result: SurfaceAssessment = {
        schemaVersion: '1.0', mode, generatedAt: now, scope: new URL(page.url).origin,
        ...detected,
        limitations: [
            'This is a bounded HTTP surface assessment, not a penetration test or a clean bill of health.',
            'No SQL injection, authentication bypass, password testing, database queries or port scans were performed.',
            'Database services hidden behind the application cannot be assessed from a website URL.',
            'Signatures and version banners may be inaccurate or quoted content; review the evidence.',
            'This release does not assess database runtime CVEs, WordPress plugin advisories or known-exploitation status.',
        ],
        intelligence: { source: 'GitHub-reviewed Composer advisories', status: 'not-requested', detail: 'No package inventory supplied.' },
    };
    for (const hit of tech) if (!result.components.some(c => c.name === hit.name)) result.components.push({ name: hit.name, version: hit.version, source: `${page.url} — ${hit.evidence}`, confidence: 'medium' });
    result.coverage.push({ checkId: 'database-services', label: 'Database network access and permissions', status: 'not-assessed', detail: 'Web responses do not establish database port exposure, database authorisation, encryption or runtime patch status.' });
    if (mode === 'owner') {
        for (const path of OWNER_PATHS) {
            if (signal?.aborted) throw new TargetError('Assessment cancelled.', 499);
            const target = new URL(path, result.scope);
            const checkId = `owner-${path.replace(/[^a-z0-9]+/gi, '-')}`;
            if (robots.error) { result.coverage.push({ checkId, label: path, status: 'blocked', detail: 'Robots policy could not be established; owner-only checks were skipped.' }); continue; }
            if (!robotsAllows(robots, path)) { result.coverage.push({ checkId, label: path, status: 'blocked', detail: 'Skipped because robots.txt disallows this path.' }); continue; }
            if (robots.crawlDelay && robots.crawlDelay > 5) { result.coverage.push({ checkId, label: path, status: 'blocked', detail: 'Declared crawl delay exceeds the owner assessment time budget; check manually.' }); continue; }
            await politeDelay(target.host, Math.max(750, (robots.crawlDelay || 0) * 1000));
            try {
                const res = await fetcher(target, { timeoutMs: 5000, maxBytes: 32 * 1024, maxRedirects: 2, sameOrigin: result.scope, signal });
                if (res.status === 401 || res.status === 403 || res.status === 429) { result.coverage.push({ checkId, label: path, status: 'blocked', detail: `HTTP ${res.status}; content could not be assessed.` }); continue; }
                // An HTTP 200 alone is never sufficient: soft-404s and SPA fallbacks must not become findings.
                const d = detectExposures(res, now);
                if (res.status >= 200 && res.status < 300) {
                    result.findings.push(...d.findings.filter(f => !['php-version', 'php-eol'].includes(f.checkId)));
                    result.components.push(...d.components);
                }
                result.coverage.push({ checkId, label: path, status: res.truncated || res.status >= 500 ? 'partial' : 'completed', detail: `HTTP ${res.status}. ${res.truncated ? 'Only a bounded response prefix was inspected.' : res.status >= 500 ? 'Server error; endpoint availability remains uncertain.' : 'Checked response signatures; absence of a match does not establish that other paths are protected.'}` });
            } catch (e) {
                result.coverage.push({ checkId, label: path, status: e instanceof TargetError && e.status === 403 ? 'blocked' : 'error', detail: e instanceof TargetError && e.status === 403 ? 'Redirect outside the approved origin or blocked destination.' : 'Request failed or timed out; endpoint not assessed.' });
            }
        }
    } else result.coverage.push({ checkId: 'owner-paths', label: 'Owner-only configuration and administration checks', status: 'not-assessed', detail: 'Public mode does not request diagnostic, configuration or administration paths. Prove DNS control to enable the five bounded owner checks.' });

    const advisories = await assessAdvisories(inventory, page.url, now, fetcher);
    result.findings.push(...advisories.findings);
    result.coverage.push(advisories.coverage);
    result.intelligence = advisories.intelligence;
    const weight = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    result.findings = [...new Map(result.findings.map(f => [f.id, f])).values()].sort((a, b) => weight[b.severity] - weight[a.severity] || a.id.localeCompare(b.id));
    result.components = [...new Map(result.components.map(c => [`${c.name}:${c.version || ''}:${c.source}`, c])).values()].slice(0, 100);
    return redactReport(result);
}
