import React from 'react';

export const Disclaimer: React.FC = () => (
    <div className="bg-hacker-dark-2 border-2 border-hacker-red/40 p-4 text-sm text-text-secondary">
        <h4 className="font-bold text-base text-hacker-red uppercase tracking-widest mb-2 text-center">// Rules of Engagement //</h4>
        <ul className="list-disc list-inside space-y-1">
            <li>GhostWires Mk.IV performs <strong className="text-text-primary">passive OSINT on publicly available data only</strong>: DNS, a single TLS handshake, HTTP response headers, public HTML, robots.txt, sitemaps, security.txt, Certificate Transparency logs (crt.sh) and the Wayback Machine.</li>
            <li>Only scan targets you own or are <strong className="text-text-primary">explicitly authorised</strong> to assess. You are responsible for complying with the Computer Misuse Act 1990, GDPR/UK GDPR and the target's terms of service.</li>
            <li>No exploitation, brute forcing, credential testing or vulnerability probing is performed. Crawls are rate-limited, capped and honour robots.txt; private/internal addresses are blocked (SSRF guard).</li>
            <li>AI keys are <strong className="text-text-primary">bring-your-own</strong>: held only in this tab, sent only with AI requests, never stored by the server, and wiped when you close or reload the tab.</li>
            <li>Harvested contact data may be personal data — minimise, protect and delete it when no longer needed. AI narratives are generated from collected facts and may still contain errors; verify against the primary source.</li>
        </ul>
    </div>
);
