// GhostWires Mk.IV — pluggable LLM providers behind one tiny interface.
// Gemini (Google GenAI SDK) + any OpenAI-compatible endpoint (NVIDIA NIM, OpenRouter, Groq).
import { GoogleGenAI } from '@google/genai';
import type { AIProviderId, ProviderInfo, ProvidersResponse } from '../../types';

export interface ChatTurn { role: 'system' | 'user' | 'assistant'; content: string; }
export interface VisionInput { mime: string; base64: string; }

export interface AIProvider {
    info: ProviderInfo;
    complete(messages: ChatTurn[], opts?: { json?: boolean; maxTokens?: number; temperature?: number; timeoutMs?: number }): Promise<string>;
    stream(messages: ChatTurn[], onDelta: (t: string) => void): Promise<void>;
    describeImage?(prompt: string, image: VisionInput): Promise<string>;
}

const env = (k: string) => (process.env[k] || '').trim();

/** Hosted multi-user mode: ignore any server-side keys, visitors must bring their own. */
export const byokOnly = () => env('GHOSTWIRES_BYOK_ONLY') === '1';
const serverKey = (...names: string[]) => byokOnly() ? '' : (names.map(env).find(Boolean) || '');

/** Remove any occurrence of a secret from text before it is logged or returned. */
export function redact(text: string, secret?: string | null): string {
    let out = String(text ?? '');
    if (secret && secret.length >= 8) out = out.split(secret).join('[redacted]');
    return out
        .replace(/nvapi-[A-Za-z0-9_-]{8,}/g, 'nvapi-[redacted]')
        .replace(/AIza[0-9A-Za-z_-]{20,}/g, 'AIza[redacted]')
        .replace(/sk-or-[A-Za-z0-9_-]{8,}/g, 'sk-or-[redacted]')
        .replace(/gsk_[A-Za-z0-9]{8,}/g, 'gsk_[redacted]')
        .replace(/([?&]key=)[^&\s]+/gi, '$1[redacted]')
        .replace(/(Bearer\s+)[A-Za-z0-9._-]{8,}/gi, '$1[redacted]');
}

// ---------------------------------------------------------------- Gemini
function geminiProvider(byokKey?: string): AIProvider {
    const key = byokKey || serverKey('GEMINI_API_KEY', 'API_KEY');
    const model = env('GEMINI_MODEL') || 'gemini-2.5-flash';
    let client: GoogleGenAI | null = null;
    const get = () => { if (!key) throw new Error('No Google Gemini API key supplied.'); return (client ??= new GoogleGenAI({ apiKey: key })); };
    const split = (messages: ChatTurn[]) => ({
        systemInstruction: messages.filter(m => m.role === 'system').map(m => m.content).join('\n\n') || undefined,
        contents: messages.filter(m => m.role !== 'system').map(m => ({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.content }] })),
    });
    return {
        info: { id: 'gemini', label: 'Google Gemini', model, configured: !!key, vision: true },
        async complete(messages, opts = {}) {
            const { systemInstruction, contents } = split(messages);
            const job = get().models.generateContent({
                model, contents,
                config: { systemInstruction, temperature: opts.temperature ?? 0.3, maxOutputTokens: opts.maxTokens, ...(opts.json ? { responseMimeType: 'application/json' } : {}) },
            });
            const r = opts.timeoutMs
                ? await Promise.race([job, new Promise<never>((_, rej) => setTimeout(() => rej(Object.assign(new Error('Google Gemini request timed out.'), { status: 504 })), opts.timeoutMs))])
                : await job;
            return r.text || '';
        },
        async stream(messages, onDelta) {
            const { systemInstruction, contents } = split(messages);
            const s = await get().models.generateContentStream({ model, contents, config: { systemInstruction, temperature: 0.4 } });
            for await (const chunk of s) if (chunk.text) onDelta(chunk.text);
        },
        async describeImage(prompt, image) {
            const r = await get().models.generateContent({
                model, contents: [{ role: 'user', parts: [{ text: prompt }, { inlineData: { mimeType: image.mime, data: image.base64 } }] }],
            });
            return (r.text || '').trim();
        },
    };
}

// ---------------------------------------------------------------- OpenAI-compatible
interface OAIConfig { id: AIProviderId; label: string; baseUrl: string; keyEnv: string; model: string; visionModel?: string; }

function openAICompatProvider(cfg: OAIConfig, byokKey?: string): AIProvider {
    const key = byokKey || serverKey(cfg.keyEnv);
    const headers = () => {
        if (!key) throw new Error(`No ${cfg.label} API key supplied.`);
        return { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json', Accept: 'application/json', 'X-Title': 'GhostWires Mk.IV' } as Record<string, string>;
    };
    const call = async (body: any, timeoutMs = Number(env('AI_TIMEOUT_MS')) || 180000) => {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), timeoutMs);
        try {
            const res = await fetch(`${cfg.baseUrl}/chat/completions`, { method: 'POST', headers: headers(), body: JSON.stringify(body), signal: ctrl.signal });
            if (!res.ok) {
                const detail = redact((await res.text()).slice(0, 300), key);
                const hint = res.status === 401 || res.status === 403 ? ' — check that your API key is valid for this provider.' : '';
                throw Object.assign(new Error(`${cfg.label} HTTP ${res.status}: ${detail}${hint}`), { status: res.status === 401 || res.status === 403 ? 401 : 502 });
            }
            return res;
        } catch (e: any) {
            if (e?.name === 'AbortError') throw Object.assign(new Error(`${cfg.label} request timed out — free-tier endpoints can be busy, try again.`), { status: 504 });
            throw e;
        } finally { clearTimeout(t); }
    };
    const toOAI = (m: ChatTurn[]) => m.map(x => ({ role: x.role, content: x.content }));
    return {
        info: { id: cfg.id, label: cfg.label, model: cfg.model, configured: !!key, vision: !!cfg.visionModel },
        async complete(messages, opts = {}) {
            const body: any = { model: cfg.model, messages: toOAI(messages), temperature: opts.temperature ?? 0.3, max_tokens: opts.maxTokens ?? 2048 };
            if (opts.json && cfg.id !== 'nim') body.response_format = { type: 'json_object' };
            const res = await call(body, opts.timeoutMs);
            const data: any = await res.json();
            return data?.choices?.[0]?.message?.content || '';
        },
        async stream(messages, onDelta) {
            const res = await call({ model: cfg.model, messages: toOAI(messages), temperature: 0.4, max_tokens: 1500, stream: true });
            const reader = res.body!.getReader();
            const dec = new TextDecoder();
            let buf = '';
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                buf += dec.decode(value, { stream: true });
                const lines = buf.split('\n');
                buf = lines.pop() || '';
                for (const line of lines) {
                    const l = line.trim();
                    if (!l.startsWith('data:')) continue;
                    const payload = l.slice(5).trim();
                    if (payload === '[DONE]') return;
                    try { const d = JSON.parse(payload)?.choices?.[0]?.delta?.content; if (d) onDelta(d); } catch { /* partial */ }
                }
            }
        },
        describeImage: cfg.visionModel ? async (prompt, image) => {
            const res = await call({
                model: cfg.visionModel, max_tokens: 160, temperature: 0.2,
                messages: [{ role: 'user', content: [{ type: 'text', text: prompt }, { type: 'image_url', image_url: { url: `data:${image.mime};base64,${image.base64}` } }] }],
            }, 90000);
            const data: any = await res.json();
            return (data?.choices?.[0]?.message?.content || '').trim();
        } : undefined,
    };
}

// ---------------------------------------------------------------- Registry
const OAI: Record<Exclude<AIProviderId, 'gemini'>, () => OAIConfig> = {
    nim: () => ({
        id: 'nim', label: 'NVIDIA NIM', baseUrl: env('NIM_BASE_URL') || 'https://integrate.api.nvidia.com/v1', keyEnv: 'NVIDIA_API_KEY',
        model: env('NIM_MODEL') || 'meta/llama-3.2-11b-vision-instruct',
        visionModel: env('NIM_VISION_MODEL') || 'meta/llama-3.2-11b-vision-instruct',
    }),
    openrouter: () => ({
        id: 'openrouter', label: 'OpenRouter (free models)', baseUrl: 'https://openrouter.ai/api/v1', keyEnv: 'OPENROUTER_API_KEY',
        model: env('OPENROUTER_MODEL') || 'google/gemma-4-31b-it:free',
    }),
    groq: () => ({
        id: 'groq', label: 'Groq', baseUrl: 'https://api.groq.com/openai/v1', keyEnv: 'GROQ_API_KEY',
        model: env('GROQ_MODEL') || 'llama-3.3-70b-versatile',
    }),
};
const IDS: AIProviderId[] = ['gemini', 'nim', 'openrouter', 'groq'];
export const isProviderId = (x: unknown): x is AIProviderId => typeof x === 'string' && (IDS as string[]).includes(x);

/** Build a provider. With byokKey, a fresh single-use instance is created and never cached. */
function make(id: AIProviderId, byokKey?: string): AIProvider {
    return id === 'gemini' ? geminiProvider(byokKey) : openAICompatProvider(OAI[id](), byokKey);
}

let serverRegistry: Record<AIProviderId, AIProvider> | null = null;
function server(): Record<AIProviderId, AIProvider> {
    return (serverRegistry ??= Object.fromEntries(IDS.map(id => [id, make(id)])) as Record<AIProviderId, AIProvider>);
}

export function defaultProvider(): AIProviderId | null {
    const all = server();
    const wanted = env('AI_PROVIDER').toLowerCase();
    if (isProviderId(wanted) && all[wanted].info.configured) return wanted;
    // Default: Gemini if its key exists, otherwise NIM, then the other free paths.
    for (const id of IDS) if (all[id].info.configured) return id;
    return null;
}

export function listProviders(): ProvidersResponse {
    return { default: defaultProvider(), byokOnly: byokOnly(), providers: IDS.map(id => server()[id].info) };
}

/**
 * Resolve the provider for ONE request. A visitor-supplied key (BYOK) always wins over server env.
 * The BYOK instance lives only for the duration of the request and is garbage-collected afterwards.
 */
export function getProvider(id?: string | null, byokKey?: string | null): AIProvider {
    if (byokKey) {
        if (!isProviderId(id)) throw Object.assign(new Error('Select which provider your API key belongs to.'), { status: 400 });
        return make(id, byokKey);
    }
    const all = server();
    const chosen = isProviderId(id) ? id : defaultProvider();
    if (!chosen) throw Object.assign(new Error('No AI key available. Add your own API key (🔑 button) — NVIDIA NIM keys are free at build.nvidia.com. Deterministic OSINT works without AI.'), { status: 401 });
    const p = all[chosen];
    if (!p.info.configured) throw Object.assign(new Error(`${p.info.label}: no API key. Add your own key with the 🔑 button.`), { status: 401 });
    return p;
}
