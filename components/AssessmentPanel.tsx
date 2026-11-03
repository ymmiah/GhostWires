import React, { useState } from 'react';
import type { SurfaceAssessment } from '../types';
import { Chip, sevTone } from './ui';

export const AssessmentPanel: React.FC<{ assessment?: SurfaceAssessment }> = ({ assessment: a }) => {
    const [filter, setFilter] = useState('all');
    if (!a) return <p className="text-text-secondary text-sm">This legacy report does not contain a structured surface assessment. Run a new assessment.</p>;
    const visible = a.findings.filter(f => filter === 'all' || f.severity === filter);
    return <section aria-label="Attack surface findings" className="space-y-4">
        <div className="border border-cyber-blue/40 bg-cyber-blue/5 p-4">
            <div className="flex flex-wrap justify-between items-center gap-3">
                <div><h3 className="text-lg text-cyber-blue font-bold">What an outsider can observe</h3><p className="text-xs text-text-secondary mt-1 break-all">{a.mode === 'owner' ? 'DNS-verified owner assessment' : 'Public surface review'} · {a.scope}</p></div>
                <span className="text-2xl text-text-primary">{a.findings.length} <span className="text-xs">findings</span></span>
            </div>
            <p className="text-xs text-text-secondary mt-3">Exposure and version matches require context. Zero findings does not establish that the site or its databases are secure.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
            <label htmlFor="finding-severity" className="text-xs text-text-secondary">Severity</label>
            <select id="finding-severity" value={filter} onChange={e => setFilter(e.target.value)} className="bg-hacker-dark border border-hacker-green/40 p-2 text-xs text-text-primary">
                {['all', 'critical', 'high', 'medium', 'low', 'info'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <span className="text-xs text-text-secondary">Severity describes impact; confidence describes the strength of the evidence.</span>
        </div>
        {visible.map(f => <article key={f.id} className="border border-hacker-green/30 bg-hacker-dark-2 p-4 space-y-3">
            <div className="flex flex-wrap gap-2"><Chip tone={sevTone(f.severity)}>{f.severity}</Chip><Chip tone={f.status === 'potential-vulnerability' ? 'yellow' : 'blue'}>{f.status.replaceAll('-', ' ')}</Chip><Chip>{f.confidence} confidence</Chip></div>
            <h4 className="text-text-primary font-bold">{f.title}</h4>
            <p className="text-[11px] text-text-secondary break-all">{f.id} · {f.asset} · {new Date(f.observedAt).toLocaleString('en-GB')}</p>
            <div className="text-sm text-text-primary space-y-2">
                <p><strong className="text-cyber-blue">Impact: </strong>{f.impact}</p>
                <div className="bg-black/20 p-3 text-xs break-words"><strong>Evidence</strong><ul className="list-disc pl-5 mt-2 space-y-1">{f.evidence.map((e, i) => <li key={i}>{e}</li>)}</ul></div>
                <p><strong className="text-hacker-green">Fix: </strong>{f.remediation}</p>
                <p><strong className="text-cyber-blue">Verify: </strong>{f.verification}</p>
                {f.limitations.map((l, i) => <p key={i} className="text-xs text-yellow-300">{l}</p>)}
                {f.advisory && <p className="text-xs text-text-secondary">{f.advisory.id}{f.advisory.cve ? ` · ${f.advisory.cve}` : ''} · Known exploitation: not assessed</p>}
                <div className="flex flex-wrap gap-3 text-xs">{f.references.map(ref => <a key={ref} href={ref} target="_blank" rel="noopener noreferrer" className="text-cyber-blue underline break-all">{new URL(ref).hostname}</a>)}</div>
            </div>
        </article>)}
        {!visible.length && <p className="border border-hacker-green/20 p-4 text-sm text-text-secondary">{a.findings.length ? 'No findings match this filter.' : 'No exposure signatures matched the inspected responses. Review coverage and limitations below.'}</p>}
        <details className="border border-hacker-green/30 p-3" open>
            <summary className="cursor-pointer text-sm text-cyber-blue">Coverage and gaps</summary>
            <div className="mt-3 space-y-3">{a.coverage.map(c => <div key={c.checkId} className="text-xs border-t border-hacker-green/10 pt-2"><div className="flex flex-wrap gap-2 items-center"><strong className="text-text-primary">{c.label}</strong><Chip tone={c.status === 'completed' ? 'green' : c.status === 'error' ? 'red' : 'yellow'}>{c.status}</Chip></div><p className="mt-1 text-text-secondary">{c.detail}</p></div>)}</div>
        </details>
        <div className="text-xs text-text-secondary border border-hacker-green/20 p-3 space-y-2"><p><strong>Intelligence:</strong> {a.intelligence.source} · {a.intelligence.status}{a.intelligence.retrievedAt ? ` · retrieved ${new Date(a.intelligence.retrievedAt).toLocaleString('en-GB')}` : ''}</p><p>{a.intelligence.detail}</p>{a.limitations.map(l => <p key={l}>{l}</p>)}</div>
    </section>;
};
