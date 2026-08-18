import React from 'react';
import type { ExtractionResult, ExtractedLink, AdvancedReconResult, OSINTResult, Technology, Vulnerability, AccessibilityIssue, SEOPerformanceResult, PageContent, CMSPlugin, Person } from '../types';
import { CopyToClipboard } from './CopyToClipboard';
import { ContentLanguageCard } from './ContentLanguageCard';
import { AccessibilityCard } from './AccessibilityCard';
import { Card } from './Card';
import { createAbsoluteUrl } from '../utils';

interface ResultsDisplayProps {
    result: ExtractionResult;
    baseUrl: string;
    onAnalyzeImages: () => Promise<void>;
    isAnalyzingImages: boolean;
    onDownloadReport: () => void;
    onNewScan: () => void;
    proxyBuilder: (url: string) => string;
    onCrawlSite: () => void;
    isCrawling: boolean;
    crawledPages: PageContent[];
}

// Icons
const MetaIcon = () => <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /></svg>;
const SummaryIcon = () => <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" /></svg>;
const TextIcon = () => <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h7" /></svg>;
const ImageIcon = () => <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M3 9a2 2 0 012-2h.93a2 2 0 001.664-.89l.812-1.22A2 2 0 0110.07 4h3.86a2 2 0 011.664.89l.812 1.22A2 2 0 0018.07 7H19a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V9z" /><circle cx="12" cy="13" r="3" /></svg>;
const LinkIcon = () => <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /></svg>;
const SiteCrawlerIcon = () => <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2h1a2 2 0 002-2v-1a2 2 0 012-2h1.945M7.884 5.06l.542.903a2 2 0 001.76 1.037h1.628a2 2 0 001.76-1.037l.542-.903M12 20.945V18m-8.116-4.945a2 2 0 01-2.242 0C.734 14.542 0 12.863 0 11c0-3.866 3.582-7 8-7s8 3.134 8 7c0 1.863-.734 3.542-1.884 4.945a2 2 0 01-2.242 0" /></svg>;
const SparklesIcon = () => <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 3v4M3 5h4M17 3v4M19 5h-4M12 3v4M10 5h4M5 17v4M3 19h4M17 17v4M19 19h-4M12 17v4M10 19h4" /></svg>;
const AdvancedReconIcon = () => <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M5.636 18.364a9 9 0 010-12.728m12.728 0a9 9 0 010 12.728m-9.9-2.829a5 5 0 117.07-7.071" /></svg>;
const OSINTIcon = () => <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>;
const VulnerabilityIcon = () => <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 inline mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>;
const DownloadIcon = () => <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>;
const SeoIcon = () => <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" /></svg>;
const PerfIcon = () => <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>;
const NewScanIcon = () => <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h5M20 20v-5h-5M4 20h5v-5M20 4h-5v5" /></svg>

const hasOsintData = (osint?: OSINTResult): boolean => {
    if (!osint) return false;
    return osint.emails.length > 0 || osint.phoneNumbers.length > 0 || osint.addresses.length > 0 || osint.peopleLinked?.length > 0 || (osint.socialLinks && Object.values(osint.socialLinks).some(v => v));
}

const hasAdvancedReconData = (recon?: AdvancedReconResult): boolean => {
    if (!recon) return false;
    return (
        (recon.owner && recon.owner !== 'N/A') ||
        (recon.hostingPlatform && recon.hostingPlatform !== 'N/A') ||
        (recon.serverIP && recon.serverIP !== 'N/A') ||
        (recon.platform && recon.platform !== 'N/A') ||
        (recon.waf && recon.waf !== 'N/A') ||
        (recon.technologies && recon.technologies.length > 0) ||
        (recon.vulnerabilities && recon.vulnerabilities.length > 0)
    );
}

const DataListItem: React.FC<{ item: string, copyable?: boolean }> = ({ item, copyable }) => (
    <li className="flex items-center justify-between py-0.5">
        <span className="truncate">{item}</span>
        {copyable && <CopyToClipboard textToCopy={item} />}
    </li>
);

const getSeverityClass = (severity: Vulnerability['severity']) => {
    switch (severity) {
        case 'Critical': return 'bg-hacker-red text-white';
        case 'High': return 'bg-red-500 text-white';
        case 'Medium': return 'bg-yellow-500 text-hacker-dark';
        case 'Low': return 'bg-hacker-green/40 text-text-primary';
        default: return 'bg-gray-500 text-text-primary';
    }
};

const getSeverityBorderClass = (severity: Vulnerability['severity']) => {
    switch (severity) {
        case 'Critical': return 'border-hacker-red';
        case 'High': return 'border-red-500';
        case 'Medium': return 'border-yellow-500';
        case 'Low': return 'border-hacker-green/40';
        default: return 'border-gray-500';
    }
};

const ReconDataItem: React.FC<{label: string, value: React.ReactNode, copyableValue?: string}> = ({label, value, copyableValue}) => (
   <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0">
       <strong className="text-hacker-green">{label}:</strong>
       <div className="flex items-center min-w-0">
           <span className="text-text-primary break-words">{value || 'N/A'}</span>
           {copyableValue && copyableValue !== 'N/A' && <CopyToClipboard textToCopy={copyableValue} />}
       </div>
   </div>
);

const ReportControls: React.FC<{onDownloadReport: () => void; onNewScan: () => void}> = ({onDownloadReport, onNewScan}) => {
    const buttonClass = "flex items-center text-sm bg-hacker-dark hover:bg-hacker-dark-2 text-hacker-green font-bold py-1 px-3 border border-hacker-green/50 transition-all duration-300 hover:shadow-glow-blue hover:text-cyber-blue hover:border-cyber-blue rounded-sm";
    return (
        <div className="flex items-center gap-2">
             <button onClick={onNewScan} className={buttonClass} title="Start New Scan">
                <NewScanIcon />
                <span className="ml-1 hidden sm:inline">New Scan</span>
            </button>
            <button onClick={onDownloadReport} className={buttonClass} title="Download Full JSON Report">
                <DownloadIcon />
                <span className="ml-1 hidden sm:inline">Report</span>
            </button>
        </div>
    );
}

const LinkAnalysisCard: React.FC<{ links: ExtractedLink[]; baseUrl: string; }> = ({ links, baseUrl }) => {
    const internalLinks = links.filter(l => l.type === 'internal');
    const externalLinks = links.filter(l => l.type === 'external');
    const socialLinks = links.filter(l => l.type === 'social');
    const totalLinks = links.length;

    const renderLinkList = (linkList: ExtractedLink[]) => (
        <div className="max-h-48 overflow-y-auto pr-2 space-y-1 text-sm mt-1">
            {linkList.map((link, i) => (
                <a key={i} href={createAbsoluteUrl(link.href, baseUrl)} target="_blank" rel="noopener noreferrer" className="block text-hacker-green hover:underline truncate" title={createAbsoluteUrl(link.href, baseUrl)}>
                    {link.text || link.href}
                </a>
            ))}
        </div>
    );
    
    if (totalLinks === 0) {
        return <p className="text-text-secondary">No significant links found.</p>;
    }

    return (
        <div className="space-y-1">
            <div>
                <div className="w-full flex h-3 rounded-sm overflow-hidden bg-hacker-dark">
                    <div className="bg-hacker-green" style={{ width: `${(internalLinks.length / totalLinks) * 100}%` }} title="Internal Links"></div>
                    <div className="bg-sky-500" style={{ width: `${(externalLinks.length / totalLinks) * 100}%` }} title="External Links"></div>
                    <div className="bg-purple-500" style={{ width: `${(socialLinks.length / totalLinks) * 100}%` }} title="Social Links"></div>
                </div>
                <div className="flex justify-between text-xs mt-1 text-text-secondary">
                    <span><span className="text-hacker-green">●</span> Internal ({internalLinks.length})</span>
                    <span><span className="text-sky-500">●</span> External ({externalLinks.length})</span>
                    <span><span className="text-purple-500">●</span> Social ({socialLinks.length})</span>
                </div>
            </div>
            <details className="text-text-primary" open>
                <summary className="cursor-pointer font-bold text-hacker-green hover:underline">Internal Links ({internalLinks.length})</summary>
                {renderLinkList(internalLinks)}
            </details>
            <details className="text-text-primary">
                <summary className="cursor-pointer font-bold text-hacker-green hover:underline">External Links ({externalLinks.length})</summary>
                {renderLinkList(externalLinks)}
            </details>
            <details className="text-text-primary">
                <summary className="cursor-pointer font-bold text-hacker-green hover:underline">Social Links ({socialLinks.length})</summary>
                {renderLinkList(socialLinks)}
            </details>
        </div>
    );
}

const SEOPerformanceCard: React.FC<{data: SEOPerformanceResult}> = ({data}) => {
    return (
        <div className="text-sm space-y-1 text-text-primary">
            <ReconDataItem label="Title Tag" value={data.titleTag} copyableValue={data.titleTag} />
            <ReconDataItem label="Word Count" value={data.wordCount} />
            {data.h1Tags && data.h1Tags.length > 0 && (
                <div>
                    <strong className="text-hacker-green">H1 Tags:</strong>
                    <ul className="list-disc list-inside ml-2">
                        {data.h1Tags.map((tag, i) => <li key={i}>{tag}</li>)}
                    </ul>
                </div>
            )}
            {data.socialMeta && (
                <div className="pt-1 border-t border-hacker-green/30">
                     <strong className="text-hacker-green">Social Meta:</strong>
                     <div className="pl-2 space-y-0.5 text-xs">
                        <ReconDataItem label="OG:Title" value={data.socialMeta.ogTitle} />
                        <ReconDataItem label="OG:Description" value={data.socialMeta.ogDescription} />
                     </div>
                </div>
            )}
            {data.performanceHints && data.performanceHints.length > 0 && (
                 <div className="pt-1 border-t border-hacker-green/30">
                    <strong className="text-hacker-green flex items-center gap-1"><PerfIcon /> Performance Hints:</strong>
                    <ul className="list-disc list-inside ml-2 text-xs">
                        {data.performanceHints.map((hint, i) => <li key={i}>{hint}</li>)}
                    </ul>
                </div>
            )}
        </div>
    );
};

const AdvancedReconCard: React.FC<{data: AdvancedReconResult}> = ({data}) => (
    <div className="text-sm space-y-1 text-text-primary">
        <ReconDataItem label="Owner" value={data.owner} copyableValue={data.owner} />
        <ReconDataItem label="Host" value={data.hostingPlatform} copyableValue={data.hostingPlatform} />
        <ReconDataItem label="Platform" value={data.platform} copyableValue={data.platform} />
        <ReconDataItem label="Server IP" value={data.serverIP} copyableValue={data.serverIP} />
        {data.serverLocation && <ReconDataItem label="Location" value={`${data.serverLocation.city}, ${data.serverLocation.country}`} />}
        {data.waf && <ReconDataItem label="WAF" value={data.waf} />}
        {data.cmsTheme && <ReconDataItem label="CMS Theme" value={`${data.cmsTheme.name} ${data.cmsTheme.version || ''}`} />}
        
        {data.technologies && data.technologies.length > 0 && (
            <div className="pt-1 border-t border-hacker-green/30">
                <strong className="text-hacker-green">Technologies:</strong>
                 <div className="flex flex-wrap gap-1 mt-1">
                    {data.technologies.map((tech, i) => <span key={i} className="bg-hacker-dark text-xs text-text-secondary px-2 py-0.5 rounded">{tech.name} {tech.version}</span>)}
                </div>
            </div>
        )}
        {data.cmsPlugins && data.cmsPlugins.length > 0 && (
            <div className="pt-1 border-t border-hacker-green/30">
                <strong className="text-hacker-green">CMS Plugins:</strong>
                 <div className="max-h-24 overflow-y-auto pr-2">
                    <ul className="text-xs text-text-secondary">
                        {data.cmsPlugins.map((plugin: CMSPlugin, i) => <li key={i}>{plugin.name} {plugin.version || ''}</li>)}
                    </ul>
                </div>
            </div>
        )}

        {data.vulnerabilities && data.vulnerabilities.length > 0 && (
            <div className="pt-1 border-t border-hacker-green/30">
                <strong className="text-hacker-green flex items-center gap-1"><VulnerabilityIcon /> Potential Vulnerabilities:</strong>
                <div className="space-y-1 mt-1 max-h-40 overflow-y-auto pr-2">
                    {data.vulnerabilities.map((vuln, i) => (
                        <div key={i} className={`bg-hacker-dark p-1 text-xs border-l-2 ${getSeverityBorderClass(vuln.severity)}`}>
                            <div className="flex justify-between items-center">
                                <strong className="text-text-primary">{vuln.cve}</strong>
                                <span className={`px-2 py-0.5 text-xs rounded-full ${getSeverityClass(vuln.severity)}`}>{vuln.severity}</span>
                            </div>
                            <p className="text-text-secondary">{vuln.description}</p>
                        </div>
                    ))}
                </div>
            </div>
        )}
    </div>
);

const OsintCard: React.FC<{data: OSINTResult}> = ({data}) => (
    <div className="text-sm space-y-1 text-text-primary">
        {data.emails.length > 0 && (
            <div>
                <strong className="text-hacker-green">Emails:</strong>
                <ul className="text-xs max-h-20 overflow-y-auto pr-2">{data.emails.map(e => <DataListItem key={e} item={e} copyable />)}</ul>
            </div>
        )}
        {data.phoneNumbers.length > 0 && (
            <div>
                <strong className="text-hacker-green">Phone Numbers:</strong>
                <ul className="text-xs max-h-20 overflow-y-auto pr-2">{data.phoneNumbers.map(p => <DataListItem key={p} item={p} copyable />)}</ul>
            </div>
        )}
        {data.peopleLinked.length > 0 && (
             <div>
                <strong className="text-hacker-green">People Linked:</strong>
                <ul className="text-xs max-h-20 overflow-y-auto pr-2">
                    {data.peopleLinked.map((p: Person) => <DataListItem key={p.name} item={`${p.name} - ${p.title}`} />)}
                </ul>
            </div>
        )}
        {data.socialLinks && Object.values(data.socialLinks).some(v => v) && (
            <div>
                <strong className="text-hacker-green">Social Links:</strong>
                <ul className="text-xs max-h-20 overflow-y-auto pr-2">
                    {Object.entries(data.socialLinks).map(([key, value]) => value ? <DataListItem key={key} item={`${key}: ${value}`} /> : null)}
                </ul>
            </div>
        )}
    </div>
);


export const ResultsDisplay: React.FC<ResultsDisplayProps> = ({
    result,
    baseUrl,
    onAnalyzeImages,
    isAnalyzingImages,
    onDownloadReport,
    onNewScan,
    proxyBuilder,
    onCrawlSite,
    isCrawling,
    crawledPages
}) => {
    const { 
        summary, 
        mainContent, 
        metaDescription,
        metaKeywords, 
        images, 
        links, 
        advancedRecon, 
        osint,
        seoPerformance,
        accessibilityIssues,
        accessibilityScore,
        contentLanguage
    } = result;

    return (
        <div className="space-y-4">
            <div className="flex justify-between items-center flex-wrap gap-2">
                <h2 className="text-2xl text-cyber-blue font-bold text-shadow-glow-blue">Reconnaissance Report</h2>
                <ReportControls onDownloadReport={onDownloadReport} onNewScan={onNewScan} />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2">
                
                <div className="lg:col-span-2">
                    <Card title="Executive Summary" icon={<SummaryIcon />} bodyClassName="text-sm text-text-primary">
                        <p>{summary || 'No summary available.'}</p>
                    </Card>
                </div>

                <Card title="Meta Intelligence" icon={<MetaIcon />} bodyClassName="text-sm text-text-primary">
                     <div className="space-y-1">
                        <ReconDataItem label="Description" value={metaDescription} />
                        <div>
                            <strong className="text-hacker-green">Keywords:</strong>
                            {metaKeywords && metaKeywords.length > 0 ? (
                                <div className="flex flex-wrap gap-1 mt-1">
                                    {metaKeywords.map((kw, i) => <span key={i} className="bg-hacker-dark text-xs text-text-secondary px-2 py-0.5 rounded">{kw}</span>)}
                                </div>
                            ) : <span className="text-text-secondary ml-2">None Found</span>}
                        </div>
                    </div>
                </Card>
                
                {seoPerformance && (
                     <Card title="SEO Performance" icon={<SeoIcon />}>
                        <SEOPerformanceCard data={seoPerformance} />
                     </Card>
                 )}
                
                <div className="lg:col-span-4">
                    <Card title="Key Content Extraction" icon={<TextIcon />} bodyClassName="text-sm text-text-primary max-h-60 overflow-y-auto">
                        <p className="whitespace-pre-wrap">{mainContent || 'No main content extracted.'}</p>
                    </Card>
                </div>

                 <div className="lg:col-span-2">
                    {hasAdvancedReconData(advancedRecon) ? (
                        <Card title="Advanced Recon" icon={<AdvancedReconIcon />}>
                            <AdvancedReconCard data={advancedRecon} />
                        </Card>
                    ) : (
                         <Card title="Advanced Recon" icon={<AdvancedReconIcon />}>
                            <p className="text-text-secondary">No advanced reconnaissance data found.</p>
                         </Card>
                    )}
                 </div>

                 <div className="lg:col-span-2">
                    {hasOsintData(osint) ? (
                        <Card title="OSINT Data Points" icon={<OSINTIcon />}>
                            <OsintCard data={osint} />
                        </Card>
                     ) : (
                         <Card title="OSINT Data Points" icon={<OSINTIcon />}>
                            <p className="text-text-secondary">No OSINT data points discovered.</p>
                         </Card>
                     )}
                 </div>
                 
                 {contentLanguage && (
                    <div className="lg:col-span-2">
                        <ContentLanguageCard data={contentLanguage} />
                    </div>
                 )}
                 
                 {accessibilityIssues && (
                     <div className="lg:col-span-2">
                        <AccessibilityCard issues={accessibilityIssues} score={accessibilityScore} />
                    </div>
                 )}

                <div className="lg:col-span-2">
                    <Card title="Link Analysis" icon={<LinkIcon />}>
                        <LinkAnalysisCard links={links} baseUrl={baseUrl} />
                    </Card>
                </div>
                
                <div className="lg:col-span-2">
                    <Card title="Extracted Images" icon={<ImageIcon />} bodyClassName="!p-1">
                        {images && images.length > 0 ? (
                            <>
                                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-1">
                                    {images.map((img, index) => {
                                        const imageUrl = createAbsoluteUrl(img.src, baseUrl);
                                        // Conditionally apply the proxy only for HTTP/S URLs.
                                        const finalSrc = imageUrl.startsWith('http') ? proxyBuilder(imageUrl) : imageUrl;
                                        
                                        // Gracefully hide the image container on error.
                                        const handleError = (e: React.SyntheticEvent<HTMLImageElement, Event>) => {
                                            const container = e.currentTarget.parentElement;
                                            if (container) {
                                                container.style.display = 'none';
                                            }
                                        };

                                        return (
                                            <div key={index} className="group relative aspect-square bg-hacker-dark">
                                                <img 
                                                    src={finalSrc} 
                                                    alt={img.alt} 
                                                    className="w-full h-full object-cover"
                                                    onError={handleError}
                                                />
                                                <div className="absolute inset-0 bg-black/70 opacity-0 group-hover:opacity-100 transition-opacity p-1 text-xs overflow-y-auto">
                                                    <p className="text-text-primary font-bold break-words">{img.alt || 'No alt text'}</p>
                                                    {img.detailedDescription && <p className="text-cyber-blue mt-1">{img.detailedDescription}</p>}
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                                <button
                                    onClick={onAnalyzeImages}
                                    disabled={isAnalyzingImages}
                                    className="w-full mt-1 flex items-center justify-center bg-hacker-green/10 hover:bg-cyber-blue/20 text-hacker-green hover:text-cyber-blue font-bold py-2 px-2 border border-hacker-green hover:border-cyber-blue transition-all duration-300 disabled:bg-hacker-dark-2 disabled:text-hacker-green/40 disabled:border-hacker-green/40 disabled:cursor-not-allowed text-xs"
                                >
                                    {isAnalyzingImages ? 'Analyzing...' : <><SparklesIcon /><span className="ml-2">Analyze Images with AI</span></>}
                                </button>
                            </>
                        ) : <p className="text-text-secondary p-2">No images found.</p>}
                    </Card>
                </div>

                <div className="lg:col-span-4">
                    <Card title="Deep Site Crawler" icon={<SiteCrawlerIcon />} headerActions={
                         <button onClick={onCrawlSite} disabled={isCrawling} className="flex items-center text-xs bg-hacker-dark hover:bg-hacker-dark-2 text-hacker-green font-bold py-1 px-2 border border-hacker-green/50 transition-all duration-300 hover:text-cyber-blue hover:border-cyber-blue rounded-sm disabled:cursor-not-allowed disabled:opacity-50">
                            {isCrawling ? 'Crawling...' : 'Start Crawl'}
                        </button>
                    }>
                       {crawledPages.length > 0 ? (
                            <div className="max-h-60 overflow-y-auto pr-2">
                                {crawledPages.map(page => (
                                    <div key={page.url} className="p-1 border-b border-hacker-green/20">
                                        <a href={page.url} target="_blank" rel="noopener noreferrer" className="font-bold text-hacker-green hover:underline truncate block">{page.title}</a>
                                        <p className="text-xs text-text-secondary truncate" title={page.url}>{page.url}</p>
                                        <p className="text-sm text-text-primary mt-1">{page.summary}</p>
                                    </div>
                                ))}
                            </div>
                       ) : <p className="text-text-secondary">No pages crawled yet. Click "Start Crawl" to analyze internal links.</p>}
                    </Card>
                </div>
            </div>
        </div>
    );
};