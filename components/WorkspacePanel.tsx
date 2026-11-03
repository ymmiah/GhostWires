import React, { useCallback, useEffect, useRef, useState } from 'react';
import { workspaceApi } from '../api';
import type { Investigation, InvestigationSummary, ReconReport, ReviewState, WorkspaceSession } from '../types';
import { AssessmentPanel } from './AssessmentPanel';
import { Chip } from './ui';

const button = 'border border-cyber-blue/50 text-cyber-blue px-3 py-2 text-xs disabled:opacity-40';
const field = 'w-full bg-hacker-dark border border-hacker-green/40 p-2 text-sm text-text-primary';

export const WorkspacePanel: React.FC<{ report: ReconReport | null; onIdentityChange?: () => void }> = ({ report, onIdentityChange }) => {
    const [session, setSession] = useState<WorkspaceSession | null>(null);
    const [items, setItems] = useState<InvestigationSummary[]>([]);
    const [selected, setSelected] = useState<Investigation | null>(null);
    const [email, setEmail] = useState(''), [password, setPassword] = useState('');
    const [state, setState] = useState<ReviewState>('open'), [note, setNote] = useState('');
    const [busy, setBusy] = useState(false), [error, setError] = useState('');
    const [confirmDelete, setConfirmDelete] = useState(false);
    const generation = useRef(0);
    const actionStamp = useRef(0);
    const identity = useRef('');
    const acceptSession = (s: WorkspaceSession) => {
        const key = s.user ? `${s.user.workspace}:${s.user.email}` : '';
        if (key !== identity.current) { generation.current++; setSelected(null); setItems([]); setNote(''); onIdentityChange?.(); }
        identity.current = key; setSession(s);
    };
    const refresh = useCallback(async () => {
        try { const s = await workspaceApi.session(); acceptSession(s); if (s.user) { const stamp = generation.current; const rows = await workspaceApi.list(); if (stamp === generation.current) setItems(rows.investigations); } }
        catch { setError('Workspace is temporarily unavailable.'); }
    }, []);
    useEffect(() => {
        refresh();
        const focus = () => { setSelected(null); setItems([]); generation.current++; refresh(); };
        window.addEventListener('focus', focus);
        return () => { window.removeEventListener('focus', focus); generation.current++; };
    }, [refresh]);
    const run = async (action: () => Promise<void>) => {
        actionStamp.current = generation.current;
        setBusy(true); setError('');
        try { await action(); }
        catch (e: any) {
            setError(e.message);
            if (e.status === 401 || e.status === 403) await refresh();
        } finally { setBusy(false); }
    };
    const select = (item: Investigation) => { if (actionStamp.current !== generation.current) return; setSelected(item); setState(item.state); setNote(''); setConfirmDelete(false); };
    const reloadList = async () => { const stamp = generation.current; const rows = await workspaceApi.list(); if (stamp === generation.current) setItems(rows.investigations); };
    const writer = session?.user && session.user.role !== 'viewer';
    const canSave = writer && report?.assessment?.mode === 'owner' && !!report.workspaceReceipt;
    return <details className="mt-4 border border-hacker-green/30 bg-hacker-dark-2 text-text-primary">
        <summary className="cursor-pointer px-3 py-3 text-sm text-cyber-blue">Workspace <span className="text-xs text-text-secondary">· saved investigations{session?.user ? ` · ${session.user.workspace}` : ''}</span></summary>
        <div className="border-t border-hacker-green/20 p-3 space-y-4">
            {!session ? <p className="text-xs text-text-secondary">Checking workspace availability…</p> : !session.enabled ? <p className="text-xs text-text-secondary">Saved investigations are unavailable on this deployment. You can still run assessments and export reports.</p> : !session.user ? <form onSubmit={e => { e.preventDefault(); const candidate = password; setPassword(''); run(async () => { acceptSession(await workspaceApi.login(email, candidate)); await reloadList(); }); }} className="space-y-3 max-w-md">
                <p className="text-xs text-text-secondary">Sign in to save DNS-verified assessments and track your review. Accounts are provisioned by the deployment owner.</p>
                <label className="block text-xs">Email<input type="email" autoComplete="username" required value={email} onChange={e => setEmail(e.target.value)} className={`${field} mt-1`} disabled={busy} /></label>
                <label className="block text-xs">Password<input type="password" autoComplete="current-password" required maxLength={256} value={password} onChange={e => setPassword(e.target.value)} className={`${field} mt-1`} disabled={busy} /></label>
                <button className={button} disabled={busy}>Sign in</button>
            </form> : <>
                <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
                    <p className="break-all">{session.user.email} <Chip>{session.user.role}</Chip> <span className="text-text-secondary">· {session.retentionDays}-day retention</span></p>
                    <button className={button} disabled={busy} onClick={() => run(async () => { await workspaceApi.logout(); acceptSession({ enabled: true, retentionDays: session.retentionDays }); })}>Sign out</button>
                </div>
                {writer && <div className="space-y-2"><button className={button} disabled={busy || !canSave} onClick={() => report && run(async () => { select(await workspaceApi.save(report)); await reloadList(); })}>Save current assessment</button>{!canSave && <p className="text-xs text-text-secondary">While signed in, run a fresh verified-owner assessment before saving. Evidence proofs expire after 15 minutes.</p>}</div>}
                <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)] gap-4">
                    <div className="space-y-2 min-w-0">
                        <div className="flex items-center justify-between gap-2"><h3 className="text-sm font-bold">Investigations</h3><button className="text-xs text-cyber-blue underline" disabled={busy} onClick={() => run(reloadList)}>Refresh</button></div>
                        {!items.length && <p className="text-xs text-text-secondary">No saved investigations.</p>}
                        <div className="max-h-96 overflow-auto space-y-2">{items.map(item => <button key={item.id} disabled={busy} onClick={() => run(async () => { select(await workspaceApi.get(item.id)); })} className={`w-full text-left border p-3 text-xs ${selected?.id === item.id ? 'border-cyber-blue bg-cyber-blue/5' : 'border-hacker-green/20'}`}><strong className="block break-all">{item.title}</strong><span className="block mt-1 text-text-secondary">{item.state} · {item.findingCount} findings{item.kevCount ? ` · ${item.kevCount} KEV` : ''}</span><span className="block mt-1 text-text-secondary">{new Date(item.createdAt).toLocaleString('en-GB')}</span></button>)}</div>
                    </div>
                    {selected ? <section className="space-y-4 min-w-0" aria-label="Investigation detail">
                        <div><h3 className="text-sm font-bold break-all">{selected.title}</h3><p className="text-xs text-text-secondary mt-1">{selected.state} · expires {new Date(selected.expiresAt).toLocaleString('en-GB')}</p></div>
                        {writer && <form className="space-y-2" onSubmit={e => { e.preventDefault(); run(async () => { select(await workspaceApi.review(selected.id, state, note, selected.version)); await reloadList(); }); }}>
                            <label className="block text-xs">Review state<select aria-label="Review state" value={state} disabled={busy} onChange={e => setState(e.target.value as ReviewState)} className={`${field} mt-1`}>{(['open', 'in-review', 'resolved', 'accepted-risk'] as const).map(s => <option key={s} value={s}>{s}</option>)}</select></label>
                            <label className="block text-xs">Review note<textarea maxLength={2000} rows={2} disabled={busy} value={note} onChange={e => setNote(e.target.value)} className={`${field} mt-1`} placeholder="Reason, evidence or next step" /></label>
                            <p className="text-xs text-text-secondary">Resolved and accepted risk require a reason. Review state does not verify that a vulnerability was fixed.</p>
                            <button className={button} disabled={busy}>Save review</button>
                        </form>}
                        <div><h4 className="text-xs font-bold text-cyber-blue mb-2">Evidence timeline</h4><ol className="space-y-3 max-h-72 overflow-auto border-l border-cyber-blue/40 pl-3">{selected.timeline.map(event => <li key={event.sequence} className="text-xs"><p className="text-text-secondary">{new Date(event.at).toLocaleString('en-GB')} · {event.actor}</p><p className="mt-1 whitespace-pre-wrap break-words">{event.detail}</p></li>)}</ol></div>
                        <details><summary className="cursor-pointer text-xs text-cyber-blue">Saved findings ({selected.findingCount})</summary><div className="mt-3"><AssessmentPanel assessment={selected.assessment} /></div></details>
                        {session.user.role === 'owner' && <div className="text-xs">{confirmDelete ? <div className="space-y-2"><p>Delete this saved investigation and its timeline?</p><button className="border border-hacker-red px-3 py-2 text-hacker-red mr-2" disabled={busy} onClick={() => run(async () => { await workspaceApi.delete(selected.id); setSelected(null); setConfirmDelete(false); await reloadList(); })}>Delete permanently</button><button className={button} onClick={() => setConfirmDelete(false)}>Cancel</button></div> : <button className="text-hacker-red underline" onClick={() => setConfirmDelete(true)}>Delete investigation</button>}</div>}
                    </section> : <p className="text-xs text-text-secondary">Select an investigation to view its evidence and review history.</p>}
                </div>
            </>}
            {error && <p role="alert" className="text-xs text-hacker-red">{error}</p>}
        </div>
    </details>;
};
