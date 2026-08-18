
import React, { useState, useCallback } from 'react';
import { UrlInput } from './components/UrlInput';
import { ResultsDisplay } from './components/ResultsDisplay';
import { TerminalLog } from './components/TerminalLog';
import { Disclaimer } from './components/Disclaimer';
import { ChatInterface } from './components/ChatInterface';
import { extractWebsiteContent, analyzeImagesInDetail, createChat, extractPageContent } from './geminiService';
import type { ExtractionResult, ChatMessage, PageContent } from './types';
import type { Chat } from '@google/genai';
import { createAbsoluteUrl } from './utils';

const PROXIES: { name: string; builder: (url: string) => string }[] = [
    { name: 'RenderTron (JS Enabled)', builder: (url: string) => `https://render-tron.appspot.com/render/${url}` },
    { name: 'AllOrigins', builder: (url: string) => `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}` },
    { name: 'CodeTabs', builder: (url: string) => `https://api.codetabs.com/v1/proxy?quest=${url}` }
];

const App: React.FC = () => {
    const [url, setUrl] = useState<string>('https://example.com');
    const [extractionResult, setExtractionResult] = useState<ExtractionResult | null>(null);
    const [isLoading, setIsLoading] = useState<boolean>(false);
    const [isAnalyzingImages, setIsAnalyzingImages] = useState<boolean>(false);
    const [error, setError] = useState<string | null>(null);
    const [lastFetchedHtml, setLastFetchedHtml] = useState<string>('');
    const [logMessages, setLogMessages] = useState<string[]>([]);
    const [successfulProxyBuilder, setSuccessfulProxyBuilder] = useState<((url: string) => string) | null>(null);

    const [chatSession, setChatSession] = useState<Chat | null>(null);
    const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
    const [isChatLoading, setIsChatLoading] = useState<boolean>(false);

    const [crawledPages, setCrawledPages] = useState<PageContent[]>([]);
    const [isCrawling, setIsCrawling] = useState<boolean>(false);


    const handleExtract = useCallback(async () => {
        let initialUrl = url.trim();
        if (!initialUrl) {
            setError('Error: URL parameter missing.');
            return;
        }

        // Normalize URL to ensure it has a protocol, which is required for it to be a valid base URL.
        let validUrl = initialUrl;
        if (!/^(https?|ftp):\/\//i.test(validUrl)) {
            validUrl = `https://${validUrl}`;
        }
        
        // If the URL was changed, update the state.
        // This ensures subsequent renders and callbacks (like handleCrawlSite) use the correct, valid URL.
        if (validUrl !== url) {
            setUrl(validUrl);
        }

        setIsLoading(true);
        setError(null);
        setExtractionResult(null);
        setLastFetchedHtml('');
        setSuccessfulProxyBuilder(null);
        setChatSession(null);
        setChatMessages([]);
        setCrawledPages([]);
        setIsCrawling(false);
        setLogMessages([
            '> Initializing Ghostwire Mk.III Protocol...',
            '> Establishing secure proxy link...',
        ]);

        let htmlContent = '';
        let successfulFetch = false;
        let lastError: Error | null = null;
        let usedProxyBuilder: ((url: string) => string) | null = null;
        let successfulProxyName = '';

        for (const proxy of PROXIES) {
            setLogMessages(prev => [...prev, `> Attempting connection via ${proxy.name}...`]);
            try {
                const proxyUrl = proxy.builder(validUrl);
                const response = await fetch(proxyUrl);
                if (!response.ok) {
                    throw new Error(`Proxy service responded with status: ${response.status}.`);
                }
                htmlContent = await response.text();
                if (!htmlContent) {
                    throw new Error('Data stream empty. Proxy returned no content.');
                }
                usedProxyBuilder = proxy.builder;
                successfulProxyName = proxy.name;
                setSuccessfulProxyBuilder(() => proxy.builder);
                successfulFetch = true;
                setLogMessages(prev => [...prev, `> Secure link established via ${proxy.name}.`]);
                break;
            } catch (err) {
                lastError = err as Error;
                setLogMessages(prev => [...prev, `> Connection via ${proxy.name} failed. Retrying...`]);
            }
        }
        
        if (!successfulFetch) {
            const baseMessage = `All proxy connections failed. Last error: ${lastError?.message || 'Unknown connection error.'}`;
            const detailedError = `${baseMessage}\n\nThis can happen due to network issues, browser security (CORS), or because the free, public proxy services used by this tool are temporarily offline. Please try again later or with a different URL.`;
            setError(`// ERROR: ${detailedError}`);
            setLogMessages(prev => [...prev, `> PROTOCOL FAILED. ${baseMessage}`]);
            setIsLoading(false);
            return;
        }

        if (successfulProxyName.includes('JS Enabled')) {
            setLogMessages(prev => [...prev, `> JS rendering successful. Analyzing fully-rendered DOM.`]);
        }

        try {
            setLogMessages(prev => [...prev, '> Transmitting target HTML...']);
            setLastFetchedHtml(htmlContent);
            
            setLogMessages(prev => [
                ...prev, 
                '> Engaging Ghostwire AI for deep analysis...', 
                '> Executing Threat Intel Scan...',
                '> Performing A11y & Linguistic Audit...',
                '> Data stream is live, parsing intelligence...',
            ]);
            const result = await extractWebsiteContent(validUrl, htmlContent);
            setExtractionResult(result);
            setLogMessages(prev => [...prev, '> RECONNAISSANCE COMPLETE. Data displayed below.', '> Intelligence Debriefing module online.', '> Site Crawler module online.']);
            
            try {
                const chat = createChat(result);
                setChatSession(chat);
            } catch (chatErr) {
                 console.error("Failed to initialize chat session:", chatErr);
                 setError(prev => `${prev ?? ''}\n// WARNING: Intelligence Debriefing module failed to initialize.`);
            }

        } catch (err) {
            console.error("Extraction protocol failed:", err);
            const detailedError = err instanceof Error ? err.message : "An unknown anomaly was detected during the extraction protocol.";
            setError(`// ERROR: ${detailedError}`);
            setLogMessages(prev => [...prev, `> PROTOCOL FAILED. ${detailedError}`]);
        } finally {
            setIsLoading(false);
        }
    }, [url]);

    const handleCrawlSite = useCallback(async () => {
        if (!extractionResult || !successfulProxyBuilder) return;
    
        setIsCrawling(true);
        setLogMessages(prev => [
            ...prev,
            '> Initializing Deep Site Crawler...',
            '> Compiling internal link manifest...'
        ]);
    
        const internalLinks = extractionResult.links.filter(link => link.type === 'internal' && link.href && !link.href.startsWith('#'));
        const uniqueUrls = [...new Set(internalLinks.map(link => createAbsoluteUrl(link.href, url)).filter(Boolean))];
        
        setLogMessages(prev => [...prev, `> Found ${uniqueUrls.length} unique internal pages to analyze.`]);
    
        for (const pageUrl of uniqueUrls) {
            if (pageUrl === url) continue; // Skip re-crawling the initial page
            
            setLogMessages(prev => [...prev, `> Crawling: ${pageUrl}`]);
            try {
                const proxyUrl = successfulProxyBuilder(pageUrl);
                const response = await fetch(proxyUrl);
                if (!response.ok) {
                    throw new Error(`Proxy fetch failed with status ${response.status}`);
                }
                const html = await response.text();
                if (!html) {
                    throw new Error('No content received from page.');
                }
                
                const pageData = await extractPageContent(html);
                setCrawledPages(prevPages => [...prevPages, { ...pageData, url: pageUrl }]);

            } catch (err) {
                const errorMessage = err instanceof Error ? err.message : 'Unknown error';
                setLogMessages(prev => [...prev, `> CRAWL ERROR on ${pageUrl}: ${errorMessage}`]);
            }
        }
    
        setLogMessages(prev => [...prev, '> Deep Crawl complete.']);
        setIsCrawling(false);
    }, [extractionResult, successfulProxyBuilder, url]);

    const handleAnalyzeImages = useCallback(async () => {
        if (!extractionResult?.images || !lastFetchedHtml) {
            setError("Image analysis failed: Initial data packets not found.");
            return;
        }
        
        setIsAnalyzingImages(true);
        setError(null);
        try {
            const analyzedImages = await analyzeImagesInDetail(extractionResult.images, url, lastFetchedHtml);
            
            setExtractionResult(prevResult => {
                if (!prevResult) return null;
                const analyzedImagesMap = new Map(analyzedImages.map(img => [img.src, img]));
                const updatedImages = prevResult.images.map(oldImg => {
                    const newImgData = analyzedImagesMap.get(oldImg.src);
                    return newImgData ? { ...oldImg, detailedDescription: newImgData.detailedDescription } : oldImg;
                });
                return { ...prevResult, images: updatedImages };
            });
        } catch (err) {
            console.error("Image analysis protocol failed:", err);
            setError(err instanceof Error ? `// ERROR: ${err.message}` : "// ERROR: Unknown anomaly in image analysis protocol.");
        } finally {
            setIsAnalyzingImages(false);
        }
    }, [extractionResult, lastFetchedHtml, url]);

    const handleDownloadReport = useCallback(() => {
        if (!extractionResult) return;
        try {
            const fullReport = {
                ...extractionResult,
                crawledPages: crawledPages,
            };
            const jsonString = JSON.stringify(fullReport, null, 2);
            const blob = new Blob([jsonString], { type: 'application/json' });
            const href = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = href;
            const domain = new URL(url).hostname;
            link.download = `recon-report-${domain}-${new Date().toISOString().slice(0,10)}.json`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(href);
        } catch(e) {
            console.error("Failed to generate report", e);
            setError("// ERROR: Failed to generate JSON report.");
        }
    }, [extractionResult, url, crawledPages]);

    const handleSendMessage = async (message: string) => {
        if (!chatSession || isChatLoading) return;
    
        setIsChatLoading(true);
        
        const userMessage: ChatMessage = { role: 'user', content: message };
        const modelPlaceholder: ChatMessage = { role: 'model', content: '' };
        
        setChatMessages(prev => [...prev, userMessage, modelPlaceholder]);
    
        try {
            const stream = await chatSession.sendMessageStream({ message });
            
            let accumulatedText = '';
            for await (const chunk of stream) {
                const chunkText = chunk.text;
                if (chunkText) {
                    accumulatedText += chunkText;
                    setChatMessages(prev => {
                        const newMessages = [...prev];
                        newMessages[newMessages.length - 1] = { role: 'model', content: accumulatedText };
                        return newMessages;
                    });
                }
            }

        } catch (err) {
            console.error("Chat send message failed:", err);
            const errorMessage = err instanceof Error ? err.message : "Unknown error";
            setChatMessages(prev => {
                const newMessages = [...prev];
                const lastMsg = newMessages[newMessages.length - 1];
                lastMsg.content = `// ERROR: DEBRIEFING MODULE OFFLINE. REASON: ${errorMessage}`;
                return newMessages;
            });
        } finally {
            setIsChatLoading(false);
        }
    };
    
    const handleNewScan = useCallback(() => {
        setExtractionResult(null);
        setError(null);
        setLastFetchedHtml('');
        setLogMessages([]);
        setSuccessfulProxyBuilder(null);
        setChatSession(null);
        setChatMessages([]);
        setCrawledPages([]);
        setIsCrawling(false);
    }, []);

    return (
        <div className="min-h-screen bg-transparent text-hacker-green font-mono flex flex-col">
            <main className="container mx-auto px-4 pt-12 pb-6 flex-grow">
                <header className="text-center mb-4">
                    <h1 className="inline-block text-3xl md:text-4xl font-bold text-hacker-green text-shadow-glow-green">
                        &gt; Ghostwire Mk.III<span className="blinking-cursor h-8 md:h-9 align-bottom"></span>
                    </h1>
                </header>
                
                <div className="max-w-4xl mx-auto">
                    <UrlInput
                        url={url}
                        setUrl={setUrl}
                        onExtract={handleExtract}
                        isLoading={isLoading || isCrawling}
                    />
                    
                    {error && (
                        <div className="mt-4 border border-hacker-red/50 bg-hacker-red/10 text-hacker-red px-4 py-3 text-left whitespace-pre-wrap" role="alert">
                            <p className="font-bold">SYSTEM ALERT</p>
                            <p className="text-sm">{error}</p>
                        </div>
                    )}
                </div>

                <div className="mt-6 max-w-6xl mx-auto">
                    {(isLoading || (isCrawling && !extractionResult)) && <TerminalLog messages={logMessages} />}
                    {extractionResult && successfulProxyBuilder && (
                        <div className="animate-fade-in space-y-4">
                            { (isCrawling || logMessages.length > 0) && !isLoading && <TerminalLog messages={logMessages} />}
                            <ResultsDisplay
                                result={extractionResult}
                                baseUrl={url}
                                onAnalyzeImages={handleAnalyzeImages}
                                isAnalyzingImages={isAnalyzingImages}
                                onDownloadReport={handleDownloadReport}
                                onNewScan={handleNewScan}
                                proxyBuilder={successfulProxyBuilder}
                                onCrawlSite={handleCrawlSite}
                                isCrawling={isCrawling}
                                crawledPages={crawledPages}
                             />
                            {chatSession && (
                                <ChatInterface
                                    messages={chatMessages}
                                    onSendMessage={handleSendMessage}
                                    isLoading={isChatLoading}
                                    result={extractionResult}
                                />
                             )}
                        </div>
                    )}
                </div>

                <div className="mt-6 max-w-6xl mx-auto">
                    <Disclaimer />
                </div>
            </main>
            <footer className="w-full text-center py-3 border-t border-hacker-green/30 bg-hacker-dark">
                <p className="text-sm text-text-secondary">Ghostwire Mk.III // Reconnaissance Protocol</p>
            </footer>
        </div>
    );
};

export default App;
