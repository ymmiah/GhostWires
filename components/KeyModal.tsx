import React, { useEffect, useRef, useState } from 'react';
import type { AIProviderId } from '../types';
import { api } from '../api';
import { saveKey } from '../keyVault';

const OPTIONS: { id: AIProviderId; label: string; hint: string; url: string; prefix?: string }[] = [
    { id: 'nim', label: 'NVIDIA NIM (free)', hint: 'Free developer key — build.nvidia.com → Get API Key (starts with nvapi-)', url: 'https://build.nvidia.com', prefix: 'nvapi-' },
    { id: 'gemini', label: 'Google Gemini', hint: 'Free tier — aistudio.google.com/apikey', url: 'https://aistudio.google.com/apikey', prefix: 'AIza' },
    { id: 'openrouter', label: 'OpenRouter (free models)', hint: 'openrouter.ai/keys (starts with sk-or-)', url: 'https://openrouter.ai/keys', prefix: 'sk-or-' },
    { id: 'groq', label: 'Groq', hint: 'console.groq.com/keys (starts with gsk_)', url: 'https://console.groq.com/keys', prefix: 'gsk_' },
];

export const KeyModal: React.FC<{ open: boolean; onClose: () => void; onSaved: (provider: AIProviderId, model?: string, vision?: boolean, verified?: boolean) => void }> = ({ open, onClose, onSaved }) => {
    const [provider, setProvider] = useState<AIProviderId>('nim');
    const [key, setKey] = useState('');
    const [show, setShow] = useState(false);
    const [busy, setBusy] = useState(false);
    const [err, setErr] = useState<string | null>(null);
    const inputRef = useRef<HTMLInputElement>(null);

    // Never keep the typed key around once the dialog closes.
    useEffect(() => { if (!open) { setKey(''); setShow(false); setErr(null); setBusy(false); } else setTimeout(() => inputRef.current?.focus(), 30); }, [open]);
    if (!open) return null;
    const opt = OPTIONS.find(o => o.id === provider)!;
    const looksWrong = key.trim().length > 6 && opt.prefix && !key.trim().startsWith(opt.prefix);

    const submit = async (verify: boolean) => {
        const k = key.trim();
        if (k.length < 8) { setErr('That key looks too short.'); return; }
        setBusy(true); setErr(null);
        try {
            let info: { model?: string; vision?: boolean; verified?: boolean } = {};
            if (verify) info = await api.verifyKey(provider, k);
            saveKey(provider, k);
            setKey('');
            onSaved(provider, info.model, info.vision, verify ? info.verified : false);
            onClose();
        } catch (e: any) {
            setErr(e.message);
        } finally { setBusy(false); }
    };

    return (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="gw-key-title" onKeyDown={e => e.key === 'Escape' && onClose()}>
            <div className="w-full max-w-lg bg-hacker-dark-2 border-2 border-cyber-blue/60 shadow-glow-blue p-4 space-y-3">
                <h2 id="gw-key-title" className="text-lg font-bold text-cyber-blue">🔑 Bring your own AI key</h2>
                <p className="text-xs text-text-secondary">
                    GhostWires never stores your key on the server. It stays in this tab's memory/sessionStorage only and is
                    <strong className="text-hacker-green"> wiped automatically when you close or reload the tab</strong>, press <em>Forget key</em>, or after 30 min idle.
                    It is sent only to this site's <code>/api/ai/*</code> routes, in a request header, to call the provider on your behalf.
                </p>
                <form autoComplete="off" onSubmit={e => { e.preventDefault(); submit(true); }} className="space-y-2">
                    <label className="block text-xs text-hacker-green">Provider
                        <select value={provider} onChange={e => setProvider(e.target.value as AIProviderId)} className="mt-1 w-full bg-hacker-dark text-hacker-green border border-hacker-green/40 p-1.5">
                            {OPTIONS.map(o => <option key={o.id} value={o.id}>{o.label}</option>)}
                        </select>
                    </label>
                    <p className="text-[11px] text-text-secondary">{opt.hint} · <a href={opt.url} target="_blank" rel="noopener noreferrer" className="text-cyber-blue underline">get a key</a></p>
                    <label className="block text-xs text-hacker-green">API key
                        <div className="mt-1 flex">
                            <input ref={inputRef} type={show ? 'text' : 'password'} value={key} onChange={e => setKey(e.target.value)}
                                name="gw-ephemeral-secret" autoComplete="new-password" autoCorrect="off" autoCapitalize="off" spellCheck={false}
                                data-lpignore="true" data-1p-ignore="true" data-form-type="other"
                                placeholder={`${opt.prefix ?? ''}…`} className="flex-grow bg-hacker-dark text-hacker-green border border-hacker-green/40 p-1.5 focus:outline-none focus:border-cyber-blue" />
                            <button type="button" onClick={() => setShow(s => !s)} className="px-2 border border-l-0 border-hacker-green/40 text-xs text-text-secondary hover:text-cyber-blue">{show ? 'hide' : 'show'}</button>
                        </div>
                    </label>
                    {looksWrong && <p className="text-[11px] text-yellow-300">This doesn't look like a {opt.label} key (expected prefix {opt.prefix}).</p>}
                    {err && <p className="text-xs text-hacker-red whitespace-pre-wrap">{err}</p>}
                    <div className="flex flex-wrap gap-2 justify-end pt-1">
                        <button type="button" onClick={onClose} className="text-xs px-3 py-1 border border-hacker-green/30 text-text-secondary hover:text-hacker-green">Cancel</button>
                        <button type="button" disabled={busy || !key} onClick={() => submit(false)} className="text-xs px-3 py-1 border border-hacker-green/40 text-hacker-green disabled:opacity-40">Use without test</button>
                        <button type="submit" disabled={busy || !key} className="text-xs px-3 py-1 border border-cyber-blue text-cyber-blue bg-cyber-blue/10 font-bold disabled:opacity-40">{busy ? 'Verifying (≤20 s)…' : 'Verify & use'}</button>
                    </div>
                </form>
                <p className="text-[10px] text-text-secondary">Tip: anyone with access to this open tab (or its DevTools) can see the key while it is in use — close the tab when you are done. Prefer a dedicated, low-quota key.</p>
            </div>
        </div>
    );
};
