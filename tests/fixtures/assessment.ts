import type { SurfaceAssessment } from '../../types';
export function assessment(cve = 'CVE-2026-12345'): SurfaceAssessment {
    return { schemaVersion: '1.0', mode: 'owner', generatedAt: '2026-11-03T12:00:00.000Z', scope: 'https://example.com',
        findings: [{ id: 'fixture-finding', checkId: 'composer-advisories', title: 'Fixture advisory', severity: 'high', confidence: 'medium', status: 'potential-vulnerability', asset: 'https://example.com/', observedAt: '2026-11-03T12:00:00.000Z', evidence: ['Owner inventory fixture/package@1.0.0'], impact: 'Reachability unknown', remediation: 'Update', verification: 'Recheck', limitations: ['Inventory requires verification'], references: ['https://github.com/advisories/GHSA-aaaa-bbbb-cccc'], advisory: { id: 'GHSA-aaaa-bbbb-cccc', cve, affectedRange: '< 1.0.1', knownExploited: null } }],
        components: [], coverage: [], limitations: ['No compromise is established.'], intelligence: { source: 'Fixture', status: 'current', detail: 'Test fixture' } };
}
