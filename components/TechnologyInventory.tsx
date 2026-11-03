import React, { useId, useState } from 'react';
import type { TechHit, TechnologyAdvisoryCheck } from '../types';
import { Chip } from './ui';

export const TechnologyInventory: React.FC<{ tech: TechHit[]; checks?: TechnologyAdvisoryCheck[] }> = ({ tech, checks = [] }) => {
    const [query, setQuery] = useState('');
    const [category, setCategory] = useState('all');
    const id = useId();
    const categories = [...new Set(tech.map(t => t.category))].sort();
    const visible = tech.filter(t => (category === 'all' || category === t.category) && [t.name, t.category, t.version, t.evidence, t.versionEvidence, t.versionHints?.join(' '), checks.find(c => c.technology === t.name)?.status].join(' ').toLowerCase().includes(query.toLowerCase().trim()));
    return <section aria-label="Technology inventory" className="space-y-4">
        <div className="flex flex-wrap items-end gap-3">
            <div className="flex-1 min-w-0"><label className="block text-xs text-text-secondary mb-2" htmlFor={`${id}-search`}>Search technologies, versions and evidence</label><input id={`${id}-search`} type="search" value={query} onChange={e => setQuery(e.target.value)} placeholder="WordPress, PHP, jQuery, plugin…" className="w-full rounded-lg bg-hacker-dark border border-cyber-blue/30 p-3 text-sm text-text-primary" /></div>
            <div><label htmlFor={`${id}-category`} className="block text-xs text-text-secondary mb-2">Technology category</label><select id={`${id}-category`} value={category} onChange={e => setCategory(e.target.value)} className="max-w-full rounded-lg bg-hacker-dark border border-cyber-blue/30 p-3 text-sm text-text-primary"><option value="all">All categories</option>{categories.map(c => <option key={c}>{c}</option>)}</select></div>
        </div>
        <p className="text-xs text-text-secondary">{visible.length} of {tech.length} technologies · {tech.filter(t => t.version).length} observed versions. Version claims require verification against the installed build.</p>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">{visible.map(t => {
            const check = checks.find(c => c.technology === t.name);
            return <article key={t.name} className="min-w-0 rounded-xl border border-cyber-blue/20 bg-hacker-dark-2 p-4 space-y-3">
                <div className="flex flex-wrap justify-between gap-2"><h4 className="text-base font-bold text-text-primary break-words">{t.name}</h4><Chip tone="blue">{t.category}</Chip></div>
                <p className="text-sm text-cyber-blue">{t.version ? `Version ${t.version}` : t.versionCandidates && t.versionCandidates.length > 1 ? `Conflicting versions: ${t.versionCandidates.join(', ')}` : 'Version not publicly disclosed'}</p>
                {!!t.versionHints?.length && <p className="text-xs text-text-secondary">Asset version hints: {t.versionHints.join(', ')} · not a verified installed version</p>}
                <div className="flex flex-wrap gap-2"><Chip>{t.confidence || 'medium'} confidence</Chip>{check && <Chip tone={check.findingIds.length ? 'red' : check.status === 'no-match' ? 'blue' : 'yellow'}>{check.status.replaceAll('-', ' ')}{check.findingIds.length ? ` · ${check.findingIds.length} candidates` : ''}</Chip>}</div>
                <details className="text-xs text-text-secondary"><summary className="cursor-pointer text-cyber-blue">Detection and version evidence</summary><p className="mt-2 break-all">{t.evidence}</p><p className="mt-2 break-all">{t.versionEvidence || 'No reliable product-specific version evidence found.'}</p></details>
                {check && <div className="text-xs text-text-secondary space-y-2"><p>{check.detail}</p>{check.retrievedAt && <p>NVD snapshot retrieved {new Date(check.retrievedAt).toLocaleString('en-GB')}</p>}<a href={check.searchUrl} target="_blank" rel="noopener noreferrer" className="inline-block text-cyber-blue underline">Research {t.name} vulnerabilities ↗</a></div>}
            </article>;
        })}</div>
        {!visible.length && <p className="text-sm text-text-secondary p-4 border border-cyber-blue/20 rounded-lg">{tech.length ? 'No technologies match these filters.' : 'No supported technology signatures were observed. Client-side rendering or a challenge page may hide the application.'}</p>}
    </section>;
};
