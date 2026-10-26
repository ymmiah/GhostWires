import React, { useState } from 'react';
import type { ReconReport, AIAnalysis, CrawlResult, ProviderInfo } from '../types';
import { Card } from './Card';
import { KV, Chip, CopyList, Score, Stat, sevTone } from './ui';
import { CrawlGraph } from './CrawlGraph';
import { CopyToClipboard } from './CopyToClipboard';

interface Props {
    report: ReconReport;
    analysis: AIAnalysis | null;
    aiState: { loading: boolean; error: string | null };
    onRunAI: () => void;
    provider: ProviderInfo | null;
    crawl: CrawlResult | null;
    isCrawling: boolean;
    onCrawl: (maxPages: number) => void;
    imageNotes: Record<string, { text: string; error?: string }>;
    isAnalyzingImages: boolean;
    onAnalyzeImages: (srcs: string[]) => void;
    onDownloadReport: () => void;
    onNewScan: () => void;
}

const TABS = ['Overview', 'Network', 'Headers', 'Tech', 'Contacts', 'Surface', 'Content', 'Crawl', 'AI Intel'] as const;
type Tab = typeof TABS[number];

const btn = 'flex items-center gap-1 text-xs bg-hacker-dark hover:bg-hacker-dark-2 text-hacker-green font-bold py-1 px-3 border border-hacker-green/50 transition-all hover:text-cyber-blue hover:border-cyber-blue rounded-sm disabled:opacity-40 disabled:cursor-not-allowed';
const I = (d: string) => () => <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d={d} /></svg>;
const GlobeIcon = I('M21 12a9 9 0 11-18 0 9 9 0 0118 0zM3.6 9h16.8M3.6 15h16.8M12 3a15 15 0 010 18M12 3a15 15 0 000 18');
const LockIcon = I('M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z');
const ShieldIcon = I('M9 12l2 2 4-4m5.6-4A12 12 0 0112 2.9 12 12 0 013.4 6 12 12 0 0012 21a12 12 0 008.6-15z');
const ChipIcon = I('M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z');
const UserIcon = I('M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z');
const RadarIcon = I('M5.6 18.4a9 9 0 010-12.8m12.8 0a9 9 0 010 12.8m-9.9-2.8a5 5 0 117-7');
const DocIcon = I('M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.6a1 1 0 01.7.3l5.4 5.4a1 1 0 01.3.7V19a2 2 0 01-2 2z');
const SpiderIcon = I('M13.8 10.2a4 4 0 00-5.6 0l-4 4a4 4 0 105.6 5.6l1.1-1.1m-.8-4.9a4 4 0 005.7 0l4-4a4 4 0 00-5.7-5.6l-1.1 1.1');
const BrainIcon = I('M9.7 17h4.6M12 3v1m6.4 1.6l-.7.7M21 12h-1M4 12H3m3.3-5.7l-.7-.7m2.8 9.9a5 5 0 117.1 0l-.5.5A3.4 3.4 0 0014 18.5V19a2 2 0 11-4 0v-.5c0-.9-.4-1.8-1-2.4l-.5-.5z');
const MailIcon = I('M3 8l7.9 5.3a2 2 0 002.2 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z');

const proxied = (src: string) => `/api/proxy?url=${encodeURIComponent(src)}`;

export const ResultsDisplay: React.FC<Props> = (p) => {
    const { report: r } = p;
    const [tab, setTab] = useState<Tab>('Overview');
    const [crawlSize, setCrawlSize] = useState(12);
    const missingHeaders = r.headers.findings.filter(f => !f.present);
    const internal = r.links.filter(l => l.type === 'internal');
    const external = r.links.filter(l => l.type === 'external');

    return (
        <div className="space-y-3">
            <div className="flex justify-between items-center flex-wrap gap-2">
                <div>
                    <h2 className="text-2xl text-cyber-blue font-bold text-shadow-glow-blue">Reconnaissance Report</h2>
                    <p className="text-xs text-text-secondary">{r.engine} · {r.target.finalUrl} · {new Date(r.generatedAt).toLocaleString()} · {(r.durationMs / 1000).toFixed(1)}s</p>
                </div>
                <div className="flex gap-2">
                    <button className={btn} onClick={p.onNewScan}>New Scan</button>
                    <button className={btn} onClick={p.onDownloadReport}>Export JSON</button>
                </div>
            </div>

            <div className="flex flex-wrap gap-1 border-b border-hacker-green/30" role="tablist">
                {TABS.map(t => (
                    <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)}
                        className={`px-3 py-1 text-xs sm:text-sm uppercase tracking-wider border-t border-x -mb-px ${tab === t ? 'bg-hacker-dark-2 text-cyber-blue border-cyber-blue/60' : 'text-hacker-green/70 border-transparent hover:text-hacker-green'}`}>
                        {t}{t === 'AI Intel' && p.aiState.loading ? ' …' : ''}
                    </button>
                ))}
            </div>

            {r.notes.length > 0 && (
                <div className="border border-yellow-500/40 bg-yellow-500/5 text-yellow-300 text-xs p-2 space-y-0.5">{r.notes.map(n => <p key={n}>⚠ {n}</p>)}</div>
            )}

            {tab === 'Overview' && (
                <div className="space-y-3 animate-fade-in">
                    <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2">
                        <Stat label="HTTP status" value={r.target.status} tone={r.target.status < 400 ? 'text-hacker-green' : 'text-hacker-red'} />
                        <Stat label="Header grade" value={r.headers.grade} tone={r.headers.score >= 65 ? 'text-hacker-green' : 'text-hacker-red'} />
                        <Stat label="TLS days left" value={r.tls.daysRemaining ?? '—'} tone={(r.tls.daysRemaining ?? 0) > 14 ? 'text-hacker-green' : 'text-hacker-red'} />
                        <Stat label="Technologies" value={r.tech.length} />
                        <Stat label="Emails / phones" value={`${r.contacts.emails.length}/${r.contacts.phones.length}`} />
                        <Stat label="Social profiles" value={r.contacts.socials.length} />
                        <Stat label="CT subdomains" value={r.ct.enabled ? r.ct.subdomains.length : 'off'} />
                        <Stat label="A11y score" value={r.accessibility.score} tone={r.accessibility.score >= 80 ? 'text-hacker-green' : 'text-yellow-400'} />
                    </div>
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
                        <Card title="Target" icon={<GlobeIcon />}>
                            <KV label="Input" value={r.target.input} />
                            <KV label="Final URL" value={r.target.finalUrl} copy={r.target.finalUrl} />
                            <KV label="Registrable domain" value={r.target.registrableDomain} />
                            <KV label="Resolved IPs" value={r.dns.a.concat(r.dns.aaaa).join(', ') || r.target.resolvedIPs.join(', ')} />
                            <KV label="Content" value={`${r.target.contentType} · ${(r.target.bytes / 1024).toFixed(1)} KB · ${r.target.responseTimeMs} ms`} />
                            {r.target.redirectChain.length > 0 && <KV label="Redirects" value={r.target.redirectChain.map(h => `${h.status} ${h.url}`).join(' → ')} />}
                            <KV label="Title" value={r.meta.title} />
                            <KV label="Description" value={r.meta.description} />
                        </Card>
                        <Card title="AI Executive Summary" icon={<BrainIcon />}>
                            {p.analysis ? <p className="text-sm text-text-primary">{p.analysis.summary}</p>
                                : p.aiState.loading ? <p className="text-sm text-text-secondary">Analysing verified facts with {p.provider?.label}…</p>
                                : <p className="text-sm text-text-secondary">{p.aiState.error || 'AI layer idle.'} <button className="underline text-cyber-blue" onClick={p.onRunAI} disabled={!p.provider?.configured}>Run AI analysis</button></p>}
                            {p.analysis && <p className="text-[10px] text-text-secondary mt-2">via {p.analysis.provider} · {p.analysis.model} — generated from collected facts only</p>}
                        </Card>
                    </div>
                    <Card title="Top findings" icon={<ShieldIcon />}>
                        <ul className="text-sm space-y-1">
                            {missingHeaders.filter(f => f.severity === 'high').map(f => <li key={f.header}><Chip tone="red">high</Chip> Missing <code>{f.header}</code> — {f.note}</li>)}
                            {r.dns.emailSecurity.findings.map(f => <li key={f}><Chip tone="yellow">email</Chip> {f}</li>)}
                            {r.headers.disclosure.map(d => <li key={d.header}><Chip tone="blue">disclosure</Chip> <code>{d.header}: {d.value}</code></li>)}
                            {r.tls.available && r.tls.authorized === false && <li><Chip tone="red">tls</Chip> Certificate not trusted: {r.tls.authorizationError}</li>}
                            {r.forms.some(f => f.hasPassword && !f.action.startsWith('https:')) && <li><Chip tone="red">forms</Chip> Password form posts over non-HTTPS action.</li>}
                            {!r.securityTxt.found && <li><Chip>info</Chip> No security.txt published (RFC 9116).</li>}
                        </ul>
                    </Card>
                </div>
            )}

            {tab === 'Network' && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-2 animate-fade-in">
                    <Card title={`DNS Intel (${r.dns.resolver === 'doh' ? 'DNS-over-HTTPS' : 'system resolver'})`} icon={<GlobeIcon />}>
                        <KV label="A" value={r.dns.a.join(', ')} />
                        <KV label="AAAA" value={r.dns.aaaa.join(', ')} />
                        <KV label="CNAME" value={r.dns.cname.join(', ')} />
                        <KV label="NS" value={r.dns.ns.join(', ')} />
                        <KV label="MX" value={r.dns.mx.map(m => `${m.priority} ${m.exchange}`).join(', ')} />
                        <KV label="SOA" value={r.dns.soa ? `${r.dns.soa.nsname} · ${r.dns.soa.hostmaster} · serial ${r.dns.soa.serial}` : ''} />
                        <KV label="CAA" value={r.dns.caa.join(' | ')} />
                        <KV label="PTR" value={Object.entries(r.dns.reverse).map(([ip, n]) => `${ip} → ${n.join(', ') || '—'}`).join('; ')} />
                        <details className="mt-1"><summary className="cursor-pointer text-hacker-green text-sm">TXT records ({r.dns.txt.length})</summary><CopyList items={r.dns.txt} /></details>
                        {r.dns.errors.length > 0 && <p className="text-[10px] text-text-secondary mt-1">{r.dns.errors.join(' · ')}</p>}
                    </Card>
                    <div className="space-y-2">
                        <Card title="Email Security (SPF / DMARC)" icon={<MailIcon />}>
                            <KV label="SPF" value={r.dns.emailSecurity.spf} />
                            <KV label="DMARC" value={r.dns.emailSecurity.dmarc} />
                            <KV label="Policy" value={r.dns.emailSecurity.dmarcPolicy && <Chip tone={r.dns.emailSecurity.dmarcPolicy === 'reject' ? 'green' : r.dns.emailSecurity.dmarcPolicy === 'quarantine' ? 'blue' : 'yellow'}>{r.dns.emailSecurity.dmarcPolicy}</Chip>} />
                            <ul className="text-xs text-yellow-300 mt-1 list-disc list-inside">{r.dns.emailSecurity.findings.map(f => <li key={f}>{f}</li>)}</ul>
                        </Card>
                        <Card title="SaaS Footprint (from DNS)" icon={<ChipIcon />}>
                            {r.dns.saasFootprint.length ? <div className="flex flex-wrap gap-1">{r.dns.saasFootprint.map(s => <Chip key={s} tone="blue">{s}</Chip>)}</div> : <p className="text-sm text-text-secondary">No third-party verification tokens or SPF includes observed.</p>}
                            <p className="text-[10px] text-text-secondary mt-1">Inferred from TXT domain-verification tokens and SPF includes.</p>
                        </Card>
                        <Card title="TLS Certificate" icon={<LockIcon />}>
                            {r.tls.available ? (<>
                                <KV label="Subject" value={r.tls.subject} />
                                <KV label="Issuer" value={r.tls.issuer} />
                                <KV label="Valid" value={`${r.tls.validFrom?.slice(0, 10)} → ${r.tls.validTo?.slice(0, 10)} (${r.tls.daysRemaining} days left)`} />
                                <KV label="Protocol / cipher" value={`${r.tls.protocol} · ${r.tls.cipher}`} />
                                <KV label="Trusted chain" value={r.tls.authorized ? <Chip tone="green">yes</Chip> : <Chip tone="red">{r.tls.authorizationError || 'no'}</Chip>} />
                                <KV label="SHA-256" value={<span className="text-[10px]">{r.tls.fingerprint256}</span>} copy={r.tls.fingerprint256} />
                                <details><summary className="cursor-pointer text-hacker-green text-sm">SANs ({r.tls.sans.length})</summary><CopyList items={r.tls.sans} /></details>
                            </>) : <p className="text-sm text-hacker-red">TLS unavailable: {r.tls.error}</p>}
                        </Card>
                    </div>
                </div>
            )}

            {tab === 'Headers' && (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-2 animate-fade-in">
                    <div className="lg:col-span-2">
                        <Card title="Security Header Audit" icon={<ShieldIcon />} headerActions={<Score value={r.headers.score} grade={r.headers.grade} label="grade" />}>
                            <table className="w-full text-xs">
                                <tbody>
                                    {r.headers.findings.map(f => (
                                        <tr key={f.header} className="border-b border-hacker-green/10 align-top">
                                            <td className="py-1 pr-2 font-bold text-text-primary whitespace-nowrap">{f.header}</td>
                                            <td className="py-1 pr-2">{f.present ? <Chip tone={f.severity === 'low' ? 'yellow' : 'green'}>{f.severity === 'low' ? 'weak' : 'present'}</Chip> : <Chip tone={sevTone(f.severity)}>missing · {f.severity}</Chip>}</td>
                                            <td className="py-1 text-text-secondary">{f.note}{f.value && <div className="text-cyber-blue/80 break-all mt-0.5">{f.value.slice(0, 220)}</div>}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </Card>
                    </div>
                    <div className="space-y-2">
                        <Card title="Information Disclosure" icon={<RadarIcon />}>
                            {r.headers.disclosure.length ? r.headers.disclosure.map(d => <KV key={d.header} label={d.header} value={d.value} />) : <p className="text-sm text-text-secondary">No version/stack-revealing headers.</p>}
                        </Card>
                        <Card title="Cookies" icon={<LockIcon />}>
                            {r.headers.cookies.length ? r.headers.cookies.map(c => (
                                <div key={c.name} className="text-xs flex flex-wrap gap-1 items-center py-0.5"><span className="text-text-primary font-bold mr-1">{c.name}</span>
                                    <Chip tone={c.secure ? 'green' : 'red'}>Secure</Chip><Chip tone={c.httpOnly ? 'green' : 'yellow'}>HttpOnly</Chip><Chip tone={c.sameSite ? 'green' : 'yellow'}>SameSite={c.sameSite || 'unset'}</Chip></div>
                            )) : <p className="text-sm text-text-secondary">No cookies set on first response.</p>}
                        </Card>
                        <Card title="Raw Response Headers" icon={<DocIcon />}>
                            <pre className="text-[10px] text-text-secondary whitespace-pre-wrap break-all max-h-60 overflow-y-auto">{Object.entries(r.headers.raw).map(([k, v]) => `${k}: ${v}`).join('\n')}</pre>
                        </Card>
                    </div>
                </div>
            )}

            {tab === 'Tech' && (
                <Card title={`Technology Fingerprint (${r.tech.length})`} icon={<ChipIcon />}>
                    {r.tech.length ? (
                        <table className="w-full text-sm">
                            <thead><tr className="text-left text-hacker-green text-xs uppercase"><th className="py-1">Technology</th><th>Category</th><th>Version</th><th>Evidence</th></tr></thead>
                            <tbody>{r.tech.map(t => (
                                <tr key={t.name} className="border-b border-hacker-green/10"><td className="py-1 text-text-primary font-bold">{t.name}</td><td><Chip tone="blue">{t.category}</Chip></td><td className="text-text-secondary">{t.version || '—'}</td><td className="text-[11px] text-text-secondary break-all">{t.evidence}</td></tr>
                            ))}</tbody>
                        </table>
                    ) : <p className="text-text-secondary text-sm">No signatures matched. The site may be custom-built or render client-side.</p>}
                    {r.meta.generator && <KV label="Meta generator" value={r.meta.generator} />}
                    <p className="text-[10px] text-text-secondary mt-2">Deterministic signatures over HTML, script sources, headers and cookies — each hit shows its evidence.</p>
                </Card>
            )}

            {tab === 'Contacts' && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 animate-fade-in">
                    <Card title={`Emails (${r.contacts.emails.length})`} icon={<MailIcon />}><CopyList items={r.contacts.emails} /></Card>
                    <Card title={`Phones (${r.contacts.phones.length})`} icon={<UserIcon />}><CopyList items={r.contacts.phones} /></Card>
                    <Card title={`Social Profiles (${r.contacts.socials.length})`} icon={<UserIcon />}>
                        {r.contacts.socials.length ? <ul className="text-xs space-y-0.5 max-h-56 overflow-y-auto">{r.contacts.socials.map(s => (
                            <li key={s.url} className="flex gap-2 items-center"><Chip tone="blue">{s.platform}</Chip><a className="truncate text-hacker-green hover:underline" href={s.url} target="_blank" rel="noopener noreferrer nofollow">{s.url}</a><CopyToClipboard textToCopy={s.url} /></li>
                        ))}</ul> : <p className="text-sm text-text-secondary">None observed.</p>}
                    </Card>
                    <Card title={`Addresses (${r.contacts.addresses.length})`} icon={<GlobeIcon />}><CopyList items={r.contacts.addresses} /></Card>
                    <div className="md:col-span-2 text-[10px] text-text-secondary">Sources: mailto:/tel: links, visible text (incl. "[at]/[dot]" obfuscation), schema.org JSON-LD (sameAs, email, telephone, address) and &lt;address&gt; blocks. Deduplicated. Treat as personal data.</div>
                </div>
            )}

            {tab === 'Surface' && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-2 animate-fade-in">
                    <Card title={`Certificate Transparency (${r.ct.subdomains.length})`} icon={<RadarIcon />}>
                        {!r.ct.enabled ? <p className="text-sm text-text-secondary">Disabled for this scan.</p> : r.ct.error ? <p className="text-sm text-yellow-300">{r.ct.error}</p> : (<>
                            <p className="text-xs text-text-secondary mb-1">{r.ct.certCount} unexpired certificates in public CT logs (crt.sh).</p>
                            <CopyList items={r.ct.subdomains} max="max-h-72" />
                        </>)}
                    </Card>
                    <div className="space-y-2">
                        <Card title="Wayback Machine" icon={<DocIcon />}>
                            {!r.wayback.enabled ? <p className="text-sm text-text-secondary">Disabled for this scan.</p> : (<>
                                <KV label="First seen" value={r.wayback.firstSeen} />
                                <KV label="Latest snapshot" value={r.wayback.closestUrl && <a className="text-hacker-green hover:underline" href={r.wayback.closestUrl} target="_blank" rel="noopener noreferrer">{r.wayback.closestTimestamp}</a>} />
                                <KV label="Months with captures" value={r.wayback.snapshotCount} />
                                {r.wayback.error && <p className="text-xs text-yellow-300">{r.wayback.error}</p>}
                            </>)}
                        </Card>
                        <Card title="security.txt" icon={<ShieldIcon />}>
                            {r.securityTxt.found ? (<><KV label="URL" value={r.securityTxt.url} /><KV label="Contact" value={r.securityTxt.contact.join(', ')} /><KV label="Policy" value={r.securityTxt.policy.join(', ')} /><KV label="Expires" value={r.securityTxt.expires} /></>) : <p className="text-sm text-text-secondary">Not published.</p>}
                        </Card>
                        <Card title={`robots.txt ${r.robots.found ? '' : '(not found)'}`} icon={<SpiderIcon />}>
                            {r.robots.found && (<>
                                {r.robots.crawlDelay !== undefined && <KV label="Crawl-delay" value={`${r.robots.crawlDelay}s`} />}
                                <details open><summary className="cursor-pointer text-hacker-green text-sm">Disallowed paths ({r.robots.disallow.length})</summary><CopyList items={r.robots.disallow} max="max-h-40" /></details>
                                <KV label="Declared sitemaps" value={r.robots.sitemaps.join(', ')} />
                            </>)}
                        </Card>
                        <Card title={`Sitemap ${r.sitemap.found ? `(${r.sitemap.urlCount} URLs)` : '(not found)'}`} icon={<DocIcon />}>
                            {r.sitemap.found && (<>
                                <KV label="Source" value={r.sitemap.source} />
                                {r.sitemap.nestedSitemaps.length > 0 && <details><summary className="cursor-pointer text-hacker-green text-sm">Child sitemaps ({r.sitemap.nestedSitemaps.length})</summary><CopyList items={r.sitemap.nestedSitemaps} link /></details>}
                                {r.sitemap.sample.length > 0 && <details><summary className="cursor-pointer text-hacker-green text-sm">Sample URLs</summary><CopyList items={r.sitemap.sample} link /></details>}
                            </>)}
                        </Card>
                    </div>
                </div>
            )}

            {tab === 'Content' && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-2 animate-fade-in">
                    <Card title="SEO & Social Meta" icon={<DocIcon />}>
                        <KV label="Title" value={r.meta.title} /><KV label="Description" value={r.meta.description} /><KV label="Lang" value={r.meta.lang} />
                        <KV label="Canonical" value={r.meta.canonical} /><KV label="Robots meta" value={r.meta.robotsMeta} /><KV label="Words" value={r.meta.wordCount} />
                        <KV label="H1" value={r.meta.headings.h1.join(' | ')} />
                        <KV label="Keywords" value={r.meta.keywords.join(', ')} />
                        <KV label="JSON-LD types" value={r.meta.jsonLdTypes.join(', ')} />
                        {Object.keys(r.meta.og).length > 0 && <details><summary className="cursor-pointer text-hacker-green text-sm">Open Graph ({Object.keys(r.meta.og).length})</summary>{Object.entries(r.meta.og).map(([k, v]) => <KV key={k} label={`og:${k}`} value={v} />)}</details>}
                        {Object.keys(r.meta.twitter).length > 0 && <details><summary className="cursor-pointer text-hacker-green text-sm">Twitter card ({Object.keys(r.meta.twitter).length})</summary>{Object.entries(r.meta.twitter).map(([k, v]) => <KV key={k} label={`twitter:${k}`} value={v} />)}</details>}
                    </Card>
                    <Card title="Accessibility Audit" icon={<UserIcon />} headerActions={<Score value={r.accessibility.score} label="a11y" />}>
                        {r.accessibility.issues.length ? r.accessibility.issues.map(i => (
                            <div key={i.description} className="flex items-center gap-2 text-sm py-0.5"><Chip tone={sevTone(i.impact)}>{i.impact}</Chip><span className="text-text-primary">{i.description}</span><span className="text-text-secondary">×{i.count}</span></div>
                        )) : <p className="text-sm text-hacker-green">No heuristic issues detected.</p>}
                        <p className="text-[10px] text-text-secondary mt-1">WCAG-inspired static heuristics on the served HTML — not a substitute for a full audit.</p>
                    </Card>
                    <Card title={`Links (${internal.length} internal · ${external.length} external)`} icon={<SpiderIcon />}>
                        <details open><summary className="cursor-pointer text-hacker-green text-sm">Path roots ({r.subfolders.length})</summary><div className="flex flex-wrap gap-1 my-1">{r.subfolders.map(s => <Chip key={s}>{s}</Chip>)}</div></details>
                        <details><summary className="cursor-pointer text-hacker-green text-sm">Internal</summary><CopyList items={internal.map(l => l.href)} link /></details>
                        <details><summary className="cursor-pointer text-hacker-green text-sm">External</summary><CopyList items={external.map(l => l.href)} link /></details>
                        {r.forms.length > 0 && <details><summary className="cursor-pointer text-hacker-green text-sm">Forms ({r.forms.length})</summary>{r.forms.map((f, i) => <p key={i} className="text-xs text-text-secondary">{f.method} {f.action} · {f.inputs} inputs{f.hasPassword ? ' · password' : ''}</p>)}</details>}
                    </Card>
                    <Card title={`Images (${r.images.length})`} icon={<DocIcon />} bodyClassName="!p-1" headerActions={
                        <button className={btn} disabled={p.isAnalyzingImages || !p.provider?.configured || !p.provider?.vision} onClick={() => p.onAnalyzeImages(r.images.slice(0, 6).map(i => i.src))}
                            title={p.provider && !p.provider.vision ? `${p.provider.label} model has no vision support` : 'Describe up to 6 images with the AI vision model'}>
                            {p.isAnalyzingImages ? 'Analysing…' : p.provider && !p.provider.vision ? 'Vision n/a' : 'AI Vision'}
                        </button>}>
                        {r.images.length ? (
                            <div className="grid grid-cols-3 sm:grid-cols-4 gap-1 max-h-96 overflow-y-auto">
                                {r.images.slice(0, 40).map(img => (
                                    <div key={img.src} className="group relative aspect-square bg-hacker-dark">
                                        <img src={proxied(img.src)} alt={img.alt} loading="lazy" className="w-full h-full object-contain" onError={e => { (e.currentTarget.parentElement as HTMLElement).style.opacity = '0.3'; }} />
                                        <div className="absolute inset-0 bg-black/80 opacity-0 group-hover:opacity-100 transition-opacity p-1 text-[10px] overflow-y-auto">
                                            <p className="text-text-primary font-bold break-words">{img.alt || <span className="text-hacker-red">no alt text</span>}</p>
                                            {p.imageNotes[img.src]?.text && <p className="text-cyber-blue mt-1">{p.imageNotes[img.src].text}</p>}
                                            {p.imageNotes[img.src]?.error && <p className="text-yellow-300 mt-1">{p.imageNotes[img.src].error}</p>}
                                        </div>
                                        {p.imageNotes[img.src]?.text && <span className="absolute top-0 right-0 bg-cyber-blue text-hacker-dark text-[9px] px-1">AI</span>}
                                    </div>
                                ))}
                            </div>
                        ) : <p className="text-sm text-text-secondary p-2">No images found.</p>}
                    </Card>
                </div>
            )}

            {tab === 'Crawl' && (
                <Card title="Polite Site Crawler" icon={<SpiderIcon />} headerActions={
                    <div className="flex items-center gap-2">
                        <select value={crawlSize} onChange={e => setCrawlSize(Number(e.target.value))} className="bg-hacker-dark text-hacker-green text-xs border border-hacker-green/40 p-1" disabled={p.isCrawling}>
                            {[6, 12, 18, 25].map(n => <option key={n} value={n}>{n} pages</option>)}
                        </select>
                        <button className={btn} disabled={p.isCrawling} onClick={() => p.onCrawl(crawlSize)}>{p.isCrawling ? 'Crawling…' : 'Start crawl'}</button>
                    </div>}>
                    <p className="text-[11px] text-text-secondary mb-2">Same-host BFS (depth ≤ 2), honours robots.txt and Crawl-delay (min 750 ms between requests), capped at 25 pages.</p>
                    {p.crawl ? (
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
                            <CrawlGraph crawl={p.crawl} />
                            <div className="max-h-[420px] overflow-y-auto pr-1 space-y-1">
                                {p.crawl.pages.map(pg => (
                                    <div key={pg.url} className="border-b border-hacker-green/15 pb-1 text-xs">
                                        <div className="flex gap-2 items-center"><Chip tone={pg.status && pg.status < 400 ? 'green' : 'red'}>{pg.status || 'ERR'}</Chip><Chip>d{pg.depth}</Chip>
                                            <a href={pg.url} target="_blank" rel="noopener noreferrer" className="text-hacker-green hover:underline truncate font-bold">{pg.title}</a></div>
                                        <p className="text-text-secondary truncate" title={pg.url}>{pg.url}</p>
                                        {pg.description && <p className="text-text-primary">{pg.description.slice(0, 180)}</p>}
                                        <p className="text-text-secondary">{pg.wordCount} words · {pg.outLinks} links{pg.emails.length ? ` · emails: ${pg.emails.join(', ')}` : ''}{pg.error ? ` · ${pg.error}` : ''}</p>
                                    </div>
                                ))}
                                {p.crawl.skippedByRobots.length > 0 && <p className="text-xs text-yellow-300">Skipped by robots.txt: {p.crawl.skippedByRobots.length}</p>}
                            </div>
                        </div>
                    ) : <p className="text-sm text-text-secondary">No crawl yet.</p>}
                </Card>
            )}

            {tab === 'AI Intel' && (
                <div className="space-y-2 animate-fade-in">
                    {!p.analysis && (
                        <Card title="AI Analysis" icon={<BrainIcon />}>
                            {p.aiState.loading ? <p className="text-sm text-text-secondary">Running {p.provider?.label} ({p.provider?.model}) over verified facts… free-tier endpoints can take 10–120 s.</p>
                                : <div className="text-sm text-text-secondary space-y-2"><p>{p.aiState.error || 'Not run yet.'}</p><button className={btn} onClick={p.onRunAI} disabled={!p.provider?.configured}>Run AI analysis</button></div>}
                        </Card>
                    )}
                    {p.analysis && (
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
                            <Card title="Executive Summary" icon={<BrainIcon />} headerActions={<button className={btn} onClick={p.onRunAI} disabled={p.aiState.loading}>{p.aiState.loading ? '…' : 'Re-run'}</button>}>
                                <p className="text-sm text-text-primary">{p.analysis.summary}</p>
                                <p className="text-[10px] text-text-secondary mt-2">via {p.analysis.provider} · {p.analysis.model}</p>
                            </Card>
                            <Card title="Linguistic Profile" icon={<DocIcon />}>
                                <div className="flex gap-3 items-center">
                                    <Score value={Math.round((p.analysis.sentiment + 1) * 50)} grade={p.analysis.sentiment.toFixed(2)} label="sentiment" />
                                    <div><KV label="Language" value={p.analysis.language} /><KV label="Readability" value={p.analysis.readability} /></div>
                                </div>
                                <div className="flex flex-wrap gap-1 mt-2">{p.analysis.keyTopics.map(t => <Chip key={t} tone="blue">{t}</Chip>)}</div>
                                <div className="flex flex-wrap gap-1 mt-1">{p.analysis.entities.map(t => <Chip key={t}>{t}</Chip>)}</div>
                            </Card>
                            <Card title="Security Narrative" icon={<ShieldIcon />}><p className="text-sm text-text-primary">{p.analysis.securityNarrative}</p></Card>
                            <Card title="SEO & Accessibility Narrative" icon={<UserIcon />}><p className="text-sm text-text-primary">{p.analysis.seoNarrative}</p><p className="text-sm text-text-primary mt-2">{p.analysis.a11yNarrative}</p></Card>
                            <div className="lg:col-span-2"><Card title="Prioritised Defensive Recommendations" icon={<ShieldIcon />}>
                                <ol className="list-decimal list-inside text-sm text-text-primary space-y-1">{p.analysis.recommendations.map(x => <li key={x}>{x}</li>)}</ol>
                            </Card></div>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};
