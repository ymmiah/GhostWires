// GhostWires Mk.IV — TLS certificate summary via a single handshake (node:tls)
import tls from 'node:tls';
import type { TLSIntel } from '../types';

export function tlsIntel(hostname: string, ip: string | undefined, port = 443): Promise<TLSIntel> {
    return new Promise(resolve => {
        const done = (r: TLSIntel) => { try { socket.destroy(); } catch { /* noop */ } resolve(r); };
        const socket = tls.connect({
            host: ip || hostname, port, servername: hostname, rejectUnauthorized: false, timeout: 8000,
            ALPNProtocols: ['h2', 'http/1.1'],
        }, () => {
            const cert = socket.getPeerCertificate(false);
            if (!cert || !Object.keys(cert).length) return done({ available: false, sans: [], error: 'No certificate presented' });
            const cipher = socket.getCipher();
            const validTo = new Date(cert.valid_to);
            const fmt = (o: any) => o ? Object.entries(o).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join('+') : v}`).join(', ') : '';
            done({
                available: true,
                protocol: socket.getProtocol() || undefined,
                cipher: cipher ? `${cipher.name} (${cipher.version})` : undefined,
                subject: fmt(cert.subject),
                issuer: fmt(cert.issuer),
                validFrom: new Date(cert.valid_from).toISOString(),
                validTo: validTo.toISOString(),
                daysRemaining: Math.floor((validTo.getTime() - Date.now()) / 86400000),
                sans: (cert.subjectaltname || '').split(',').map(s => s.trim().replace(/^DNS:/, '')).filter(Boolean).slice(0, 100),
                fingerprint256: cert.fingerprint256,
                serialNumber: cert.serialNumber,
                authorized: socket.authorized,
                authorizationError: socket.authorizationError ? String(socket.authorizationError) : undefined,
            });
        });
        socket.on('timeout', () => done({ available: false, sans: [], error: 'TLS handshake timed out' }));
        socket.on('error', (e: any) => done({ available: false, sans: [], error: e?.code || e?.message }));
    });
}
