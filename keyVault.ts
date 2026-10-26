// GhostWires Mk.IV — ephemeral Bring-Your-Own-Key vault (browser side).
//
// Security model:
//  • The key lives in memory + sessionStorage ONLY (never localStorage, cookies, IndexedDB, URLs).
//  • sessionStorage is scoped to this single tab and is destroyed by the browser when the tab closes.
//  • On top of that we actively wipe on `pagehide` / `beforeunload` (tab close, window close,
//    navigation away, reload), on "Forget key", and after 30 minutes of inactivity.
//  • The key is sent ONLY to this site's /api/ai/* routes in the X-GhostWires-API-Key header.
import type { AIProviderId } from './types';

export interface StoredKey { provider: AIProviderId; key: string; }

const SLOT = 'gw.byok.v1';
const IDLE_MS = 30 * 60 * 1000;
let memory: StoredKey | null = null;
const listeners = new Set<(k: StoredKey | null) => void>();
let idleTimer: number | undefined;

function emit() { listeners.forEach(l => l(memory)); }

function armIdle() {
    if (idleTimer) window.clearTimeout(idleTimer);
    if (memory) idleTimer = window.setTimeout(() => wipeKey('idle'), IDLE_MS);
}

export function loadKey(): StoredKey | null {
    if (memory) return memory;
    try {
        const raw = window.sessionStorage.getItem(SLOT);
        if (raw) memory = JSON.parse(raw);
    } catch { memory = null; }
    return memory;
}

export function saveKey(provider: AIProviderId, key: string) {
    memory = { provider, key: key.trim() };
    try { window.sessionStorage.setItem(SLOT, JSON.stringify(memory)); } catch { /* memory-only fallback */ }
    armIdle();
    emit();
}

export function wipeKey(_reason: 'user' | 'unload' | 'idle' = 'user') {
    memory = null;
    try { window.sessionStorage.removeItem(SLOT); } catch { /* ignore */ }
    if (idleTimer) window.clearTimeout(idleTimer);
    emit();
}

export function subscribe(fn: (k: StoredKey | null) => void) { listeners.add(fn); return () => { listeners.delete(fn); }; }

export function maskKey(key: string) { return key.length <= 10 ? '••••' : `${key.slice(0, 4)}••••${key.slice(-3)}`; }

/** Headers for AI requests only. */
export function authHeaders(): Record<string, string> {
    const k = loadKey();
    if (!k) return {};
    armIdle();
    return { 'X-GhostWires-API-Key': k.key, 'X-GhostWires-Provider': k.provider };
}

// Wipe when the tab/window closes or navigates away. `pagehide` is the reliable signal on mobile/Safari,
// `beforeunload` covers older desktop browsers. Both are synchronous-safe (no network needed).
let installed = false;
export function installWipeOnClose() {
    if (installed || typeof window === 'undefined') return;
    installed = true;
    window.addEventListener('pagehide', () => wipeKey('unload'));
    window.addEventListener('beforeunload', () => wipeKey('unload'));
    ['pointerdown', 'keydown'].forEach(ev => window.addEventListener(ev, () => { if (memory) armIdle(); }, { passive: true }));
    // Belt and braces: never leave a key in persistent storage from older builds.
    try { window.localStorage.removeItem(SLOT); } catch { /* ignore */ }
}
