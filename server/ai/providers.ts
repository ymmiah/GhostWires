// GhostWires Mk.IV — pluggable LLM providers behind one tiny interface.
// Gemini (Google GenAI SDK) + any OpenAI-compatible endpoint (NVIDIA NIM, OpenRouter, Groq).
import { GoogleGenAI } from '@google/genai';
import type { AIProviderId, ProviderInfo, ProvidersResponse } from '../../types';

export interface ChatTurn { role: 'system' | 'user' | 'assistant'; content: string; }
export interface VisionInput { mime: string; base64: string; }

export interface AIProvider {
    info: ProviderInfo;
    complete(messages: ChatTurn[], opts?: { json?: boolean; maxTokens?: number; temperature?: number }): Promise<string>;
    stream(messages: ChatTurn[], onDelta: (t: string) => void): Promise<void>;
    describeImage?(prompt: string, image: VisionInput): Promise<string>;
}

const env = (k: string) => (process.env[k] || '').trim();

// ---------------------------------------------------------------- Gemini
function geminiProvider(): AIProvider {
    const key = env('GEMINI_API_KEY') || env('API_KEY');
    const model = env('GEMINI_MODEL') || 'gemini-2.5-flash';
    let client: GoogleGenAI | null = null;
    const get = () => { if (!key) throw new Error('GEMINI_API_KEY is not set on the server.'); return (client ??= new GoogleGenAI({ apiKey: key })); };
    const split = (messages: ChatTurn[]) => ({
        systemInstruction: messages.filter(m => m.role === 'system').map(m => m.content).join('\n\n') || undefined,
        contents: messages.filter(m => m.role !== 'system').map(m => ({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.content }] })),
    });
    return {
        info: { id: 'gemini', label: 'Google Gemini', model, configured: !!key, vision: true },
        async complete(messages, opts = {}) {
            const { systemInstruction, contents } = split(messages);
            const r = await get().models.generateContent({
                model, contents,
                config: { systemInstruction, temperature: opts.temperature ?? 0.3, maxOutputTokens: opts.maxTokens, ...(opts.json ? { responseMimeType: 'application/json' } : {}) },
            });
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

function openAICompatProvider(cfg: OAIConfig): AIProvider {
    const key = env(cfg.keyEnv);
    const headers = () => {
        if (!key) throw new Error(`${cfg.keyEnv} is not set on the server.`);
        return { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json', Accept: 'application/json', 'X-Title': 'GhostWires Mk.IV' } as Record<string, string>;
    };
    const call = async (body: any, timeoutMs = Number(env('AI_TIMEOUT_MS')) || 180000) => {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), timeoutMs);
        try {
            const res = await fetch(`${cfg.baseUrl}/chat/completions`, { method: 'POST', headers: headers(), body: JSON.stringify(body), signal: ctrl.signal });
            if (!res.ok) {
                const detail = (await res.text()).slice(0, 300);
                throw new Error(`${cfg.label} HTTP ${res.status}: ${detail}`);
            }
            return res;
        } catch (e: any) {
            if (e?.name === 'AbortError') throw new Error(`${cfg.label} request timed out.`);
            throw e;
        } finally { clearTimeout(t); }
    };
    const toOAI = (m: ChatTurn[]) => m.map(x => ({ role: x.role, content: x.content }));
    return {
        info: { id: cfg.id, label: cfg.label, model: cfg.model, configured: !!key, vision: !!cfg.visionModel },
        async complete(messages, opts = {}) {
            const body: any = { model: cfg.model, messages: toOAI(messages), temperature: opts.temperature ?? 0.3, max_tokens: opts.maxTokens ?? 2048 };
            if (opts.json && cfg.id !== 'nim') body.response_format = { type: 'json_object' };
            const res = await call(body);
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
let registry: Record<AIProviderId, AIProvider> | null = null;
function build(): Record<AIProviderId, AIProvider> {
    return (registry ??= {
        gemini: geminiProvider(),
        nim: openAICompatProvider({
            id: 'nim', label: 'NVIDIA NIM', baseUrl: env('NIM_BASE_URL') || 'https://integrate.api.nvidia.com/v1', keyEnv: 'NVIDIA_API_KEY',
            model: env('NIM_MODEL') || 'meta/llama-3.2-11b-vision-instruct',
            visionModel: env('NIM_VISION_MODEL') || 'meta/llama-3.2-11b-vision-instruct',
        }),
        openrouter: openAICompatProvider({
            id: 'openrouter', label: 'OpenRouter (free models)', baseUrl: 'https://openrouter.ai/api/v1', keyEnv: 'OPENROUTER_API_KEY',
            model: env('OPENROUTER_MODEL') || 'google/gemma-4-31b-it:free',
        }),
        groq: openAICompatProvider({
            id: 'groq', label: 'Groq', baseUrl: 'https://api.groq.com/openai/v1', keyEnv: 'GROQ_API_KEY',
            model: env('GROQ_MODEL') || 'llama-3.3-70b-versatile',
        }),
    });
}

export function defaultProvider(): AIProviderId | null {
    const all = build();
    const wanted = env('AI_PROVIDER').toLowerCase() as AIProviderId;
    if (wanted && all[wanted]?.info.configured) return wanted;
    // Default: Gemini if its key exists, otherwise NIM, then the other free paths.
    for (const id of ['gemini', 'nim', 'openrouter', 'groq'] as AIProviderId[]) if (all[id].info.configured) return id;
    return null;
}

export function listProviders(): ProvidersResponse {
    const all = build();
    return { default: defaultProvider(), providers: Object.values(all).map(p => p.info) };
}

export function getProvider(id?: string | null): AIProvider {
    const all = build();
    const chosen = (id && id in all ? id : defaultProvider()) as AIProviderId | null;
    if (!chosen) throw Object.assign(new Error('No AI provider configured. Set NVIDIA_API_KEY (free at build.nvidia.com) or GEMINI_API_KEY on the server. Deterministic OSINT still works without AI.'), { status: 503 });
    const p = all[chosen];
    if (!p.info.configured) throw Object.assign(new Error(`${p.info.label} is not configured on the server.`), { status: 503 });
    return p;
}
