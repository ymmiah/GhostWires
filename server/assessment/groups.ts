import { createHash } from 'node:crypto';
import type { SurfaceAssessment, SurfaceFinding } from '../../types';

/** Shared surface is a reason to review together, not evidence of an attack chain. */
export function groupFindings(scope: string, findings: SurfaceFinding[]): NonNullable<SurfaceAssessment['groups']> {
    const groups = new Map<string, { title: string; reason: string; findingIds: string[] }>();
    for (const f of findings) {
        if (new URL(f.asset).origin !== scope) continue;
        const category = f.advisory ? 'dependencies' : /^(database-|environment-|php-source)/.test(f.checkId) ? 'data-exposure' : /^php-/.test(f.checkId) || f.checkId === 'phpinfo' ? 'php' : 'management';
        const titles = { dependencies: 'Dependency advisories', 'data-exposure': 'Database and configuration exposure', php: 'PHP runtime and diagnostics', management: 'Public management surface' };
        const group = groups.get(category) || { title: titles[category], reason: 'Findings share this origin and a related technical surface. No exploit chain or compromise is established.', findingIds: [] };
        group.findingIds.push(f.id); groups.set(category, group);
    }
    return [...groups].map(([category, g]) => ({ id: createHash('sha256').update(`${scope}:${category}`).digest('hex').slice(0, 16), ...g }));
}
