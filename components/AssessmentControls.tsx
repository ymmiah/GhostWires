import React, { useState } from 'react';
import { api } from '../api';
import type { AssessmentMode, InventoryPackage, OwnershipChallenge } from '../types';
import { CopyToClipboard } from './CopyToClipboard';

export interface AssessmentOptions { mode: AssessmentMode; ownershipToken?: string; inventory?: InventoryPackage[]; }
export const AssessmentControls: React.FC<{ url: string; disabled: boolean; onChange: (options: AssessmentOptions) => void }> = ({ url, disabled, onChange }) => {
    const [mode, setMode] = useState<AssessmentMode>('public');
    const [challenge, setChallenge] = useState<OwnershipChallenge | null>(null);
    const [inventory, setInventory] = useState<InventoryPackage[]>([]);
    const [consent, setConsent] = useState(false);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState('');
    const change = (m = mode, c = challenge, p = inventory, allowed = consent) => onChange({ mode: m, ownershipToken: c?.token, inventory: m === 'owner' && allowed ? p : [] });
    const btn = 'border border-cyber-blue/60 px-3 py-2 text-xs text-cyber-blue disabled:opacity-40';
    const createProof = async () => {
        setBusy(true); setError('');
        try { const c = await api.ownershipChallenge(url); setChallenge(c); change(mode, c); }
        catch (e: any) { setError(e.message); }
        finally { setBusy(false); }
    };
    const importLock = async (file: File | undefined) => {
        setInventory([]); change(mode, challenge, []); setError('');
        if (!file) return;
        if (file.size > 2 * 1024 * 1024) { setError('Use a composer.lock file smaller than 2 MB.'); return; }
        try {
            const data = JSON.parse(await file.text());
            if (!Array.isArray(data.packages)) throw new Error('Expected a composer.lock file with a packages array.');
            const rows = data.packages.map((p: any) => ({ name: String(p.name || ''), version: String(p.version || '').replace(/^v/, '') }));
            if (rows.length > 100) throw new Error('This bounded assessment supports at most 100 production packages.');
            if (rows.some((p: InventoryPackage) => !/^[a-z0-9_.-]+\/[a-z0-9_.-]+$/.test(p.name) || !/^\d+\.\d+\.\d+$/.test(p.version))) throw new Error('Only exact stable package versions are supported; development branches and pre-releases require manual review.');
            setInventory(rows); change(mode, challenge, rows);
        } catch (e: any) { setError(e.message || 'Could not read lockfile.'); }
    };
    return <fieldset disabled={disabled || busy} className="mt-4 border border-hacker-green/30 bg-hacker-dark-2 p-3 text-xs space-y-3 min-w-0">
        <legend className="px-2 text-cyber-blue">Assessment scope</legend>
        <div className="flex flex-wrap gap-4">
            <label className="flex gap-2 items-center"><input type="radio" name="assessment-mode" checked={mode === 'public'} onChange={() => { setMode('public'); change('public'); }} /> Public surface</label>
            <label className="flex gap-2 items-center"><input type="radio" name="assessment-mode" checked={mode === 'owner'} onChange={() => { setMode('owner'); change('owner'); }} /> Verified owner</label>
        </div>
        <p className="text-text-secondary">{mode === 'public' ? 'Examines the requested page and existing OSINT sources. Does not request configuration or administration paths.' : 'Requires DNS control. Adds five bounded, read-only checks on the exact origin: .env, phpinfo, phpMyAdmin, Adminer and Git HEAD. No login attempts or database queries.'}</p>
        {mode === 'owner' && <>
            <button type="button" className={btn} onClick={createProof}>{busy ? 'Creating…' : challenge ? 'Create fresh DNS proof' : 'Create DNS proof'}</button>
            {challenge && <div className="border-l-2 border-cyber-blue pl-3 space-y-2 break-all text-text-primary">
                <p>For <strong>{challenge.origin}</strong>, add this DNS TXT record:</p>
                <p>Name: <code>{challenge.recordName}</code> <CopyToClipboard textToCopy={challenge.recordName} /></p>
                <p>Value: <code>{challenge.recordValue}</code> <CopyToClipboard textToCopy={challenge.recordValue} /></p>
                <p className="text-text-secondary">Proof expires {new Date(challenge.expiresAt).toLocaleTimeString('en-GB')}. DNS is verified when you run the assessment. Use the exact origin above; cross-origin redirects are blocked.</p>
            </div>}
            <div className="space-y-2 border-t border-hacker-green/20 pt-3">
                <label className="block">Optional Composer inventory <input aria-label="Import composer.lock" type="file" accept=".lock,.json,application/json" onChange={e => importLock(e.target.files?.[0])} className="block mt-2 max-w-full" /></label>
                <p className="text-text-secondary">The file is parsed in this browser. Only production package names and exact versions are used; the full lockfile is not uploaded. Development dependencies are excluded.</p>
                <label className="flex items-start gap-2"><input type="checkbox" checked={consent} onChange={e => { setConsent(e.target.checked); change(mode, challenge, inventory, e.target.checked); }} /><span>Allow selected package names and versions to be sent to GitHub’s public advisory API.</span></label>
                {inventory.length > 0 && <p className="text-cyber-blue">{inventory.length} packages loaded · {consent ? 'advisory matching enabled' : 'not submitted without consent'}</p>}
            </div>
        </>}
        {error && <p role="alert" className="text-hacker-red">{error}</p>}
    </fieldset>;
};
