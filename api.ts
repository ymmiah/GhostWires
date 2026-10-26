// GhostWires Mk.IV — browser API client. All secrets stay on the server.
import type { ReconReport, CrawlResult, AIAnalysis, ProvidersResponse, ChatMessage } from './types';

async function post<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error((data as any).error || `${path} failed with HTTP ${res.status}`);
    return data as T;
}

export const api = {
    health: () => fetch('/api/health').then(r => r.json()),
    providers: () => fetch('/api/providers').then(r => r.json() as Promise<ProvidersResponse>),
    recon: (url: string, ct: boolean, wayback: boolean) => post<ReconReport>('/api/recon', { url, ct, wayback }),
    crawl: (url: string, maxPages: number) => post<CrawlResult>('/api/crawl', { url, maxPages }),
    analyze: (report: ReconReport, provider?: string) => post<AIAnalysis>('/api/ai/analyze', { report, provider }),
    vision: (images: string[], pageUrl: string, provider?: string) =>
        post<{ provider: string; vision: boolean; results: { src: string; detailedDescription: string; error?: string }[] }>('/api/ai/vision', { images, pageUrl, provider }),
    async chat(report: ReconReport, messages: ChatMessage[], provider: string | undefined, onDelta: (t: string) => void) {
        const res = await fetch('/api/ai/chat', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ report, messages, provider }) });
        if (!res.ok || !res.body) {
            const data = await res.json().catch(() => ({}));
            throw new Error((data as any).error || `Chat failed with HTTP ${res.status}`);
        }
        const reader = res.body.getReader();
        const dec = new TextDecoder();
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            onDelta(dec.decode(value, { stream: true }));
        }
    },
};
