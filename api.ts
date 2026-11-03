// GhostWires Mk.IV — browser API client. All secrets stay on the server.
import { authHeaders } from './keyVault';
import type { ReconReport, CrawlResult, AIAnalysis, ProvidersResponse, ChatMessage, AssessmentMode, OwnershipChallenge, InventoryPackage, WorkspaceSession, Investigation, InvestigationSummary, ReviewState } from './types';

async function post<T>(path: string, body: unknown, withKey = false, signal?: AbortSignal): Promise<T> {
    const res = await fetch(path, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', referrerPolicy: 'no-referrer',
        headers: { 'Content-Type': 'application/json', ...(withKey ? authHeaders() : {}) },
        body: JSON.stringify(body), signal,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error((data as any).error || `${path} failed with HTTP ${res.status}`);
    return data as T;
}

export const api = {
    health: () => fetch('/api/health').then(r => r.json()),
    providers: () => fetch('/api/providers').then(r => r.json() as Promise<ProvidersResponse>),
    recon: (url: string, ct: boolean, wayback: boolean, options: { mode?: AssessmentMode; ownershipToken?: string; inventory?: InventoryPackage[] } = {}, signal?: AbortSignal) => post<ReconReport>('/api/recon', { url, ct, wayback, ...options }, false, signal),
    ownershipChallenge: (url: string) => post<OwnershipChallenge>('/api/ownership/challenge', { url }),
    crawl: (url: string, maxPages: number) => post<CrawlResult>('/api/crawl', { url, maxPages }),
    analyze: (report: ReconReport, provider?: string) => post<AIAnalysis>('/api/ai/analyze', { report, provider }, true),
    vision: (images: string[], pageUrl: string, provider?: string) =>
        post<{ provider: string; vision: boolean; results: { src: string; detailedDescription: string; error?: string }[] }>('/api/ai/vision', { images, pageUrl, provider }, true),
    /** Verify a candidate key BEFORE it is stored (sent once, in a header, to this server only). */
    async verifyKey(provider: string, key: string) {
        const res = await fetch('/api/ai/verify', {
            method: 'POST', cache: 'no-store', referrerPolicy: 'no-referrer',
            headers: { 'Content-Type': 'application/json', 'X-GhostWires-API-Key': key, 'X-GhostWires-Provider': provider }, body: '{}',
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error((data as any).error || `Key check failed (HTTP ${res.status})`);
        return data as { ok: true; verified: boolean; provider: string; model: string; vision: boolean };
    },
    async chat(report: ReconReport, messages: ChatMessage[], provider: string | undefined, onDelta: (t: string) => void) {
        const res = await fetch('/api/ai/chat', {
            method: 'POST', cache: 'no-store', referrerPolicy: 'no-referrer',
            headers: { 'Content-Type': 'application/json', ...authHeaders() }, body: JSON.stringify({ report, messages, provider }),
        });
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

let workspaceCsrf = '';
async function workspaceRequest<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
    const res = await fetch(`/api/workspace${path}`, {
        method, credentials: 'same-origin', cache: 'no-store', referrerPolicy: 'no-referrer',
        headers: { ...(method === 'GET' ? {} : { 'Content-Type': 'application/json', 'X-Workspace-CSRF': workspaceCsrf }) },
        ...(method === 'GET' ? {} : { body: JSON.stringify(body || {}) }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.status === 401) workspaceCsrf = '';
    if (!res.ok) throw Object.assign(new Error(data.error || 'Workspace request failed.'), { status: res.status });
    return data as T;
}
export const workspaceApi = {
    async session() { const s = await workspaceRequest<WorkspaceSession>('/session'); workspaceCsrf = s.csrfToken || ''; return s; },
    async login(email: string, password: string) { const s = await workspaceRequest<WorkspaceSession>('/login', 'POST', { email, password }); workspaceCsrf = s.csrfToken || ''; return s; },
    async logout() { await workspaceRequest('/logout', 'POST'); workspaceCsrf = ''; },
    list: () => workspaceRequest<{ investigations: InvestigationSummary[] }>('/investigations'),
    get: (id: string) => workspaceRequest<Investigation>(`/investigations/${encodeURIComponent(id)}`),
    save: (report: ReconReport) => workspaceRequest<Investigation>('/investigations', 'POST', { assessment: report.assessment, receipt: report.workspaceReceipt }),
    review: (id: string, state: ReviewState, note: string, version: number) => workspaceRequest<Investigation>(`/investigations/${encodeURIComponent(id)}`, 'PATCH', { state, note, version }),
    delete: (id: string) => workspaceRequest(`/investigations/${encodeURIComponent(id)}`, 'DELETE'),
};
