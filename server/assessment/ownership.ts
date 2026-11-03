import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import dns from 'node:dns/promises';
import net from 'node:net';
import { assertPublicHost, normalizeTarget, TargetError } from '../net';
import type { OwnershipChallenge } from '../../types';

// Tokens deliberately expire on process restart. No proof or target inventory is persisted.
const signingKey = randomBytes(32);
const TTL = 30 * 60_000;
const sign = (payload: string) => createHmac('sha256', signingKey).update(payload).digest('base64url');

export async function createOwnershipChallenge(input: string, now = Date.now()): Promise<OwnershipChallenge> {
    const target = normalizeTarget(input);
    if (net.isIP(target.hostname.replace(/^\[|\]$/g, ''))) throw new TargetError('Owner checks require a domain with DNS TXT control.');
    await assertPublicHost(target.hostname);
    const nonce = randomBytes(24).toString('hex');
    const expires = now + TTL;
    const payload = Buffer.from(JSON.stringify({ origin: target.origin, nonce, expires })).toString('base64url');
    return { origin: target.origin, recordName: `_ghostwires.${target.hostname}`, recordValue: `ghostwires-verification=${nonce}`, token: `${payload}.${sign(payload)}`, expiresAt: new Date(expires).toISOString() };
}

export async function verifyOwnership(input: string, token: unknown, now = Date.now(), resolve = dns.resolveTxt): Promise<void> {
    const target = normalizeTarget(input);
    if (typeof token !== 'string' || token.length > 2048) throw new TargetError('Domain ownership proof is required.', 403);
    const [payload, signature, extra] = token.split('.');
    const expected = sign(payload || '');
    if (extra || !signature || signature.length !== expected.length || !timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) throw new TargetError('Invalid ownership token.', 403);
    let claim: { origin: string; nonce: string; expires: number };
    try { claim = JSON.parse(Buffer.from(payload, 'base64url').toString()); } catch { throw new TargetError('Invalid ownership token.', 403); }
    if (claim.origin !== target.origin || !/^[a-f0-9]{48}$/.test(claim.nonce) || !Number.isFinite(claim.expires) || claim.expires <= now || claim.expires > now + TTL) throw new TargetError('Ownership proof expired or belongs to a different origin.', 403);
    await assertPublicHost(target.hostname);
    let timer: ReturnType<typeof setTimeout>;
    try {
        const records = await Promise.race([resolve(`_ghostwires.${target.hostname}`), new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('DNS timeout')), 5000); })]);
        if (!records.some(parts => parts.join('') === `ghostwires-verification=${claim.nonce}`)) throw new Error('Record not found');
    } catch { throw new TargetError('DNS ownership record not found. Check the TXT value and allow time for DNS propagation.', 403); }
    finally { clearTimeout(timer!); }
}
