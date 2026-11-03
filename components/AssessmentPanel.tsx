import React, { useId, useState } from 'react';
import { TechnologyInventory } from './TechnologyInventory';
import type { SurfaceAssessment, TechHit } from '../types';
import { Chip, sevTone } from './ui';

export const AssessmentPanel: React.FC<{ assessment?: SurfaceAssessment; tech?: TechHit[] }> = ({ assessment: a, tech }) => {
    const [filter, setFilter] = useState('all');
    const [query, setQuery] = useState('');
    const [kind, setKind] = useState('all');
    const [group, setGroup] = useState('all');
    const panelId = useId();
    if (!a) return <p className="text-text-secondary text-sm">This legacy report does not contain a structured surface assessment. Run a new assessment.</p>;
    const selectedGroup = a.groups?.find(g => g.id === group);
    const visible = a.findings.filter(f => (filter === 'all' || f.severity === filter) && (!selectedGroup || selectedGroup.findingIds.includes(f.id)) && (kind === 'all' || (kind === 'advisory' ? !!f.advisory : !f.advisory)) && [f.title, f.asset, f.id, f.advisory?.cve, f.advisory?.id, f.impact, f.remediation, ...f.evidence].join(' ').toLowerCase().includes(query.toLowerCase().trim()));
    return <section aria-label="Attack surface findings" className="space-y-4">
        <div className="border border-cyber-blue/40 bg-cyber-blue/5 p-4">
            <div className="flex flex-wrap justify-between items-center gap-3">
                <div><h3 className="text-lg text-cyber-blue font-bold">What an outsider can observe</h3><p className="text-xs text-text-secondary mt-1 break-all">{a.mode === 'owner' ? 'DNS-verified owner assessment' : 'Public surface review'} · {a.scope}</p></div>
                <span className="text-2xl text-text-primary">{a.findings.length} <span className="text-xs">findings</span></span>
            </div>
            <p className="text-xs text-text-secondary mt-3">Exposure and version matches require context. Zero findings does not establish that the site or its databases are secure.</p>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">{[
            ['Observed technologies', tech?.length ?? a.components.length],
            ['Advisory candidates', a.findings.filter(f => f.advisory).length],
            ['Exposure observations', a.findings.filter(f => !f.advisory).length],
            ['Checks needing evidence', a.coverage.filter(c => c.status !== 'completed').length],
        ].map(([label, count]) => <div key={label} className="rounded-xl border border-cyber-blue/20 bg-hacker-dark-2 p-4"><strong className="block text-2xl text-text-primary mb-2">{count}</strong><span className="text-text-secondary">{label}</span></div>)}</div>
        <details className="rounded-xl border border-cyber-blue/20 p-4" open>
            <summary className="cursor-pointer font-bold text-cyber-blue">Technologies and version intelligence</summary>
            <div className="mt-4"><TechnologyInventory tech={tech || a.components.map(c => ({ name: c.name, version: c.version, evidence: c.source, confidence: c.confidence, category: 'Observed component' }))} checks={a.technologyAdvisories} /></div>
        </details>
        <h3 className="text-lg font-bold text-text-primary">Vulnerabilities and exposures</h3>
        <div><label htmlFor={`${panelId}-search`} className="block text-xs text-text-secondary mb-2">Search findings, CVEs, versions and evidence</label><input id={`${panelId}-search`} type="search" value={query} onChange={e => setQuery(e.target.value)} placeholder="CVE, PHP, database, version or fix…" className="w-full rounded-lg bg-hacker-dark border border-cyber-blue/30 p-3 text-sm text-text-primary" /></div>
        <div className="flex flex-wrap items-center gap-2">
            <label htmlFor={`${panelId}-kind`} className="text-xs text-text-secondary">Finding type</label><select id={`${panelId}-kind`} value={kind} onChange={e => setKind(e.target.value)} className="bg-hacker-dark border border-cyber-blue/30 p-2 text-xs text-text-primary"><option value="all">All types</option><option value="advisory">Vulnerability advisories</option><option value="exposure">Exposure observations</option></select>
            <label htmlFor={`${panelId}-severity`} className="text-xs text-text-secondary">Severity</label>
            <select id={`${panelId}-severity`} value={filter} onChange={e => setFilter(e.target.value)} className="bg-hacker-dark border border-hacker-green/40 p-2 text-xs text-text-primary">
                {['all', 'critical', 'high', 'medium', 'low', 'info'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            {!!a.groups?.length && <><label htmlFor={`${panelId}-group`} className="text-xs text-text-secondary">Related surface</label><select id={`${panelId}-group`} value={group} onChange={e => setGroup(e.target.value)} className="bg-hacker-dark border border-hacker-green/40 p-2 text-xs text-text-primary"><option value="all">All findings</option>{a.groups.map(g => <option key={g.id} value={g.id}>{g.title} ({g.findingIds.length})</option>)}</select></>}
            <span className="text-xs text-text-secondary">Severity describes impact; confidence describes the strength of the evidence.</span>
        </div>
        <p className="text-xs text-text-secondary">Showing {visible.length} of {a.findings.length} findings</p>
        {selectedGroup && <p className="text-xs text-text-secondary">{selectedGroup.reason}</p>}
        {a.threatIntelligence && <p className="text-xs text-text-secondary">CISA KEV: {a.threatIntelligence.status} · {a.threatIntelligence.detail}</p>}
        {visible.map(f => <article key={f.id} className="rounded-xl border border-cyber-blue/20 bg-hacker-dark-2 p-4 space-y-3">
            <div className="flex flex-wrap gap-2"><Chip tone={sevTone(f.severity)}>{f.severity}</Chip><Chip tone={f.status === 'potential-vulnerability' ? 'yellow' : 'blue'}>{f.status.replaceAll('-', ' ')}</Chip><Chip>{f.confidence} confidence</Chip></div>
            <h4 className="text-text-primary font-bold">{f.title}</h4>
            <p className="text-[11px] text-text-secondary break-all">{f.id} · {f.asset} · {new Date(f.observedAt).toLocaleString('en-GB')}</p>
            <div className="text-sm text-text-primary space-y-2">
                <p><strong className="text-cyber-blue">Impact: </strong>{f.impact}</p>
                <div className="bg-black/20 p-3 text-xs break-words"><strong>Evidence</strong><ul className="list-disc pl-5 mt-2 space-y-1">{f.evidence.map((e, i) => <li key={i}>{e}</li>)}</ul></div>
                <p><strong className="text-hacker-green">Fix: </strong>{f.remediation}</p>
                <p><strong className="text-cyber-blue">Verify: </strong>{f.verification}</p>
                {f.limitations.map((l, i) => <p key={i} className="text-xs text-yellow-300">{l}</p>)}
                {f.advisory && <p className="text-xs text-text-secondary">{f.advisory.id}{f.advisory.cve ? ` · ${f.advisory.cve}` : ''} · CISA KEV: {f.advisory.knownExploited === true ? 'listed — known exploitation elsewhere' : f.advisory.knownExploited === false ? 'not listed in this snapshot' : 'unknown / not assessed'}</p>}
                {f.advisory?.kev && <p className="text-xs text-yellow-300">KEV action: {f.advisory.kev.requiredAction} · Added {f.advisory.kev.dateAdded}. This does not establish compromise of this asset.</p>}
                <div className="flex flex-wrap gap-3 text-xs">{f.references.map(ref => <a key={ref} href={ref} target="_blank" rel="noopener noreferrer" className="text-cyber-blue underline break-all">{new URL(ref).hostname}</a>)}</div>
            </div>
        </article>)}
        {!visible.length && <p className="border border-hacker-green/20 p-4 text-sm text-text-secondary">{a.findings.length ? 'No findings match this filter.' : 'No exposure signatures matched the inspected responses. Review coverage and limitations below.'}</p>}
        <details className="rounded-xl border border-cyber-blue/20 p-4">
            <summary className="cursor-pointer text-sm text-cyber-blue">Coverage and gaps ({a.coverage.filter(c => c.status === 'completed').length}/{a.coverage.length} completed)</summary>
            <div className="mt-3 space-y-3">{a.coverage.map(c => <div key={c.checkId} className="text-xs border-t border-hacker-green/10 pt-2"><div className="flex flex-wrap gap-2 items-center"><strong className="text-text-primary">{c.label}</strong><Chip tone={c.status === 'completed' ? 'green' : c.status === 'error' ? 'red' : 'yellow'}>{c.status}</Chip></div><p className="mt-1 text-text-secondary">{c.detail}</p></div>)}</div>
        </details>
        <div className="text-xs text-text-secondary border border-hacker-green/20 p-3 space-y-2"><p><strong>Intelligence:</strong> {a.intelligence.source} · {a.intelligence.status}{a.intelligence.retrievedAt ? ` · retrieved ${new Date(a.intelligence.retrievedAt).toLocaleString('en-GB')}` : ''}</p><p>{a.intelligence.detail}</p>{a.limitations.map(l => <p key={l}>{l}</p>)}</div>
    </section>;
};
