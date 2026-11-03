/** Redact common credentials before retaining evidence or sending facts to AI. */
export function redactEvidence(value: string): string {
    return value
        .replace(/((?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|https?):\/\/)[^\s/@]+:[^\s/@]+@/gi, '$1[REDACTED]@')
        .replace(/\b((?:DB|DATABASE|MYSQL|POSTGRES|PG|MONGO|REDIS|ELASTIC|SQLSERVER|AWS|SMTP|MAIL|API|AUTH|APP|SECRET|ACCESS|PRIVATE)[A-Z0-9_]*(?:PASSWORD|PASS|SECRET|KEY|TOKEN)|PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|ACCESS_TOKEN|AUTHORIZATION)\b(["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s<,;}]+)/gi, '$1$2[REDACTED]')
        .replace(/\b(?:Bearer\s+[A-Za-z0-9._~+\/-]+=*|nvapi-[A-Za-z0-9_-]+|sk-(?:proj-)?[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16})\b/gi, '[REDACTED]')
        .replace(/([?&](?:token|api_key|secret|password|access_token)=)[^&#\s]*/gi, '$1[REDACTED]')
        .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/g, '[REDACTED PRIVATE KEY]');
}

export function redactReport<T>(value: T): T {
    if (typeof value === 'string') return redactEvidence(value) as T;
    if (Array.isArray(value)) return value.map(redactReport) as T;
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, typeof v === 'string' && /^(?:set-cookie|cookie|authorization|proxy-authorization|db_password|api_key|access_token)$/i.test(k) ? '[REDACTED]' : redactReport(v)])) as T;
    return value;
}
