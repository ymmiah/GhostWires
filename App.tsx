import React, { useState, useCallback, useEffect } from 'react';
import { UrlInput } from './components/UrlInput';
import { ResultsDisplay } from './components/ResultsDisplay';
import { TerminalLog } from './components/TerminalLog';
import { Disclaimer } from './components/Disclaimer';
import { ChatInterface } from './components/ChatInterface';
import { api } from './api';
import { KeyModal } from './components/KeyModal';
import { loadKey, wipeKey, subscribe, installWipeOnClose, maskKey, type StoredKey } from './keyVault';
import type { ReconReport, AIAnalysis, CrawlResult, ChatMessage, ProvidersResponse, AIProviderId } from './types';

const MODULES = ['SSRF guard + target normalisation', 'robots.txt policy', 'HTTP fetch + redirect chain', 'DNS intel (A/AAAA/MX/NS/TXT/SOA/CAA/PTR)', 'SPF / DMARC / SaaS footprint', 'TLS handshake + certificate', 'Security header audit', 'Technology fingerprint', 'Contact harvest (emails/phones/socials/JSON-LD)', 'Accessibility heuristics', 'Sitemap + security.txt', 'Certificate Transparency (crt.sh)', 'Wayback Machine CDX'];

const ts = () => new Date().toLocaleTimeString('en-GB', { hour12: false });

const App: React.FC = () => {
    const [url, setUrl] = useState('https://example.com');
    const [useCT, setUseCT] = useState(true);
    const [useWayback, setUseWayback] = useState(true);
    const [autoAI, setAutoAI] = useState(true);
    const [report, setReport] = useState<ReconReport | null>(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [log, setLog] = useState<string[]>([]);
    const [providers, setProviders] = useState<ProvidersResponse | null>(null);
    const [providerId, setProviderId] = useState<AIProviderId | ''>('');
    const [analysis, setAnalysis] = useState<AIAnalysis | null>(null);
    const [aiState, setAiState] = useState<{ loading: boolean; error: string | null }>({ loading: false, error: null });
    const [crawl, setCrawl] = useState<CrawlResult | null>(null);
    const [isCrawling, setIsCrawling] = useState(false);
    const [imageNotes, setImageNotes] = useState<Record<string, { text: string; error?: string }>>({});
    const [isAnalyzingImages, setIsAnalyzingImages] = useState(false);
    const [chat, setChat] = useState<ChatMessage[]>([]);
    const [isChatLoading, setIsChatLoading] = useState(false);

    const [byokKey, setByokKey] = useState<StoredKey | null>(null);
    const [keyModal, setKeyModal] = useState(false);
    const [byokInfo, setByokInfo] = useState<{ model?: string; vision?: boolean }>({});

    const push = (m: string) => setLog(prev => [...prev, `[${ts()}] ${m}`]);

    useEffect(() => {
        installWipeOnClose();
        const initial = loadKey();
        setByokKey(initial);
        if (initial) setProviderId(initial.provider);
        // Keep React state in lock-step with the vault (wipe on close / idle / forget clears state too).
        const off = subscribe(k => { setByokKey(k); if (!k) setByokInfo({}); });
        api.providers().then(p => { setProviders(p); if (!loadKey()) setProviderId(p.default || ''); })
            .catch(() => setProviders({ default: null, byokOnly: true, providers: [] }));
        return off;
    }, []);

    const serverProvider = providers?.providers.find(p => p.id === providerId) || null;
    // With a BYOK key the active provider is the key's provider and is always "configured".
    const provider = byokKey
        ? { ...(providers?.providers.find(p => p.id === byokKey.provider) || { id: byokKey.provider, label: byokKey.provider, model: '', vision: false }),
            id: byokKey.provider, configured: true, ...(byokInfo.model ? { model: byokInfo.model } : {}), ...(byokInfo.vision !== undefined ? { vision: byokInfo.vision } : {}) }
        : serverProvider;
    const forgetKey = () => { wipeKey('user'); setAnalysis(null); setChat([]); push('> BYOK key wiped from this tab.'); };

    const runAI = useCallback(async (rep: ReconReport, pid = providerId) => {
        const k = loadKey();
        if (k) pid = k.provider;
        if (!pid || (!k && !providers?.providers.find(p => p.id === pid)?.configured)) {
            setAiState({ loading: false, error: 'No AI key yet — click 🔑 Add API key (NVIDIA NIM keys are free). Deterministic OSINT is unaffected.' });
            return;
        }
        setAiState({ loading: true, error: null });
        push(`> AI layer: ${pid} analysing verified facts…`);
        try {
            const a = await api.analyze(rep, pid);
            setAnalysis(a);
            setAiState({ loading: false, error: null });
            push(`> AI analysis OK (${a.model}).`);
        } catch (e: any) {
            setAiState({ loading: false, error: `AI analysis failed: ${e.message}` });
            push(`> AI ERROR: ${e.message}`);
        }
    }, [providerId, providers]);

    const handleExtract = useCallback(async () => {
        const target = url.trim();
        if (!target) { setError('Enter a target URL or domain.'); return; }
        setIsLoading(true); setError(null); setReport(null); setAnalysis(null); setCrawl(null); setChat([]); setImageNotes({});
        setAiState({ loading: false, error: null });
        setLog([`[${ts()}] > GhostWires Mk.IV — passive OSINT pipeline engaged against ${target}`]);
        let i = 0;
        const ticker = setInterval(() => { if (i < MODULES.length) push(`> module: ${MODULES[i++]}`); }, 450);
        try {
            const rep = await api.recon(target, useCT, useWayback);
            clearInterval(ticker);
            setReport(rep);
            setUrl(rep.target.finalUrl);
            push(`> RECON COMPLETE in ${(rep.durationMs / 1000).toFixed(1)}s — ${rep.tech.length} tech, ${rep.contacts.emails.length} emails, ${rep.ct.subdomains.length} CT subdomains, headers ${rep.headers.grade}.`);
            if (autoAI && (loadKey() || providerId)) runAI(rep);
        } catch (e: any) {
            clearInterval(ticker);
            setError(`// ERROR: ${e.message}`);
            push(`> PROTOCOL FAILED: ${e.message}`);
        } finally {
            setIsLoading(false);
        }
    }, [url, useCT, useWayback, autoAI, providerId, runAI]);

    const handleCrawl = useCallback(async (maxPages: number) => {
        if (!report) return;
        setIsCrawling(true);
        push(`> Polite crawler started (≤${maxPages} pages, robots.txt honoured)…`);
        try {
            const c = await api.crawl(report.target.finalUrl, maxPages);
            setCrawl(c);
            push(`> Crawl COMPLETE: ${c.pages.length} pages, ${c.skippedByRobots.length} skipped by robots.txt.`);
        } catch (e: any) {
            push(`> CRAWL ERROR: ${e.message}`);
            setError(`// CRAWL ERROR: ${e.message}`);
        } finally { setIsCrawling(false); }
    }, [report]);

    const handleImages = useCallback(async (srcs: string[]) => {
        if (!report) return;
        setIsAnalyzingImages(true);
        try {
            const res = await api.vision(srcs, report.target.finalUrl, providerId || undefined);
            setImageNotes(prev => ({ ...prev, ...Object.fromEntries(res.results.map(r => [r.src, { text: r.detailedDescription, error: r.error }])) }));
            push(`> Vision: ${res.results.filter(r => r.detailedDescription).length}/${res.results.length} images described.`);
        } catch (e: any) {
            setError(`// VISION ERROR: ${e.message}`);
        } finally { setIsAnalyzingImages(false); }
    }, [report, providerId]);

    const handleSend = async (message: string) => {
        if (!report || isChatLoading) return;
        const history: ChatMessage[] = [...chat, { role: 'user', content: message }];
        setChat([...history, { role: 'model', content: '' }]);
        setIsChatLoading(true);
        let acc = '';
        try {
            await api.chat(report, history, providerId || undefined, d => {
                acc += d;
                setChat(prev => { const n = [...prev]; n[n.length - 1] = { role: 'model', content: acc }; return n; });
            });
        } catch (e: any) {
            setChat(prev => { const n = [...prev]; n[n.length - 1] = { role: 'model', content: `// ERROR: DEBRIEF OFFLINE — ${e.message}` }; return n; });
        } finally { setIsChatLoading(false); }
    };

    const handleDownload = () => {
        if (!report) return;
        const blob = new Blob([JSON.stringify({ report, analysis, crawl, imageNotes }, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `ghostwires-mk4-${report.target.hostname}-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(a.href);
    };

    const handleNewScan = () => { setReport(null); setAnalysis(null); setCrawl(null); setChat([]); setLog([]); setError(null); setImageNotes({}); };

    const toggle = 'flex items-center gap-1 cursor-pointer select-none';
    return (
        <div className="min-h-screen bg-transparent text-hacker-green font-mono flex flex-col">
            <main className="container mx-auto px-4 pt-10 pb-6 flex-grow">
                <header className="text-center mb-4">
                    <h1 className="inline-block text-3xl md:text-4xl font-bold text-hacker-green text-shadow-glow-green">
                        &gt; GhostWires Mk.IV<span className="blinking-cursor h-8 md:h-9 align-bottom"></span>
                    </h1>
                    <p className="text-xs text-text-secondary mt-1">Passive OSINT reconnaissance · real DNS / TLS / headers / CT / Wayback · AI-grounded debrief</p>
                </header>

                <div className="max-w-4xl mx-auto">
                    <UrlInput url={url} setUrl={setUrl} onExtract={handleExtract} isLoading={isLoading || isCrawling} />
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-secondary mt-2 px-1">
                        <label className={toggle}><input type="checkbox" checked={useCT} onChange={e => setUseCT(e.target.checked)} className="accent-[#00ff41]" /> CT logs (crt.sh)</label>
                        <label className={toggle}><input type="checkbox" checked={useWayback} onChange={e => setUseWayback(e.target.checked)} className="accent-[#00ff41]" /> Wayback</label>
                        <label className={toggle}><input type="checkbox" checked={autoAI} onChange={e => setAutoAI(e.target.checked)} className="accent-[#00ff41]" /> Auto AI analysis</label>
                        <span className="ml-auto flex items-center gap-2">
                            {byokKey ? (<>
                                <span className="text-hacker-green" title="Your key lives only in this tab and is wiped when you close it">🔒 {provider?.label} key {maskKey(byokKey.key)} · tab-only</span>
                                <button onClick={() => setKeyModal(true)} className="underline text-cyber-blue">change</button>
                                <button onClick={forgetKey} className="px-2 py-0.5 border border-hacker-red/60 text-hacker-red hover:bg-hacker-red/10">Forget key</button>
                            </>) : (<>
                                {providers?.providers.some(p => p.configured) && (
                                    <select value={providerId} onChange={e => { setProviderId(e.target.value as AIProviderId); setAnalysis(null); }} className="bg-hacker-dark text-hacker-green border border-hacker-green/40 p-0.5" title="Server-configured providers">
                                        {providers.providers.filter(p => p.configured).map(p => <option key={p.id} value={p.id}>{p.label} (server){p.vision ? ' · vision' : ''}</option>)}
                                    </select>
                                )}
                                <button onClick={() => setKeyModal(true)} className="px-2 py-0.5 border border-cyber-blue text-cyber-blue bg-cyber-blue/10 font-bold hover:shadow-glow-blue">🔑 Add API key</button>
                            </>)}
                        </span>
                    </div>
                    {provider ? <p className="text-[10px] text-text-secondary text-right px-1">AI: {provider.label}{provider.model ? ` · ${provider.model}` : ''}{!provider.vision && ' · image analysis unavailable for this provider'}</p>
                        : <p className="text-[10px] text-text-secondary text-right px-1">AI is optional — recon runs without a key. Your key is never stored server-side and is wiped when this tab closes.</p>}

                    {error && (
                        <div className="mt-3 border border-hacker-red/50 bg-hacker-red/10 text-hacker-red px-4 py-3 whitespace-pre-wrap" role="alert">
                            <p className="font-bold">SYSTEM ALERT</p><p className="text-sm">{error}</p>
                        </div>
                    )}
                </div>

                <div className="mt-5 max-w-6xl mx-auto space-y-4">
                    {log.length > 0 && <TerminalLog messages={log} active={isLoading || isCrawling || aiState.loading} />}
                    {report && (
                        <div className="animate-fade-in space-y-4">
                            <ResultsDisplay
                                report={report} analysis={analysis} aiState={aiState} onRunAI={() => runAI(report)} provider={provider}
                                crawl={crawl} isCrawling={isCrawling} onCrawl={handleCrawl}
                                imageNotes={imageNotes} isAnalyzingImages={isAnalyzingImages} onAnalyzeImages={handleImages}
                                onDownloadReport={handleDownload} onNewScan={handleNewScan}
                            />
                            <ChatInterface messages={chat} onSendMessage={handleSend} isLoading={isChatLoading} result={report}
                                providerLabel={provider ? `${provider.label} · ${provider.model}` : undefined}
                                disabledReason={provider?.configured ? null : 'Add your own API key (🔑) to enable debriefing.'} />
                        </div>
                    )}
                    <Disclaimer />
                </div>
            </main>
            <KeyModal open={keyModal} onClose={() => setKeyModal(false)} onSaved={(pid, model, vision, verified) => {
                setProviderId(pid); setByokInfo({ model, vision }); setAnalysis(null);
                push(`> BYOK key ${verified ? 'verified' : 'stored (not verified — provider slow or test skipped)'} for ${pid}${model ? ` (${model})` : ''} — held in this tab only.`);
                setAiState({ loading: false, error: null });
            }} />
            <footer className="w-full text-center py-3 border-t border-hacker-green/30 bg-hacker-dark text-xs text-text-secondary">
                <p>GhostWires Mk.IV // Passive OSINT Reconnaissance Protocol — authorised targets only</p>
                <p className="mt-0.5">Built by Yasin Mohammed Miah, Student of BCU, BSc Computing Top-Up (Hons)</p>
            </footer>
        </div>
    );
};

export default App;
