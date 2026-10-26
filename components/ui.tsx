import React from 'react';
import { CopyToClipboard } from './CopyToClipboard';
import type { Severity } from '../types';

export const KV: React.FC<{ label: string; value?: React.ReactNode; copy?: string }> = ({ label, value, copy }) => (
    <div className="flex flex-wrap items-baseline gap-x-2 py-0.5 text-sm">
        <strong className="text-hacker-green shrink-0">{label}:</strong>
        <span className="text-text-primary break-all min-w-0">{value === undefined || value === null || value === '' ? <span className="text-text-secondary">not observed</span> : value}</span>
        {copy && <CopyToClipboard textToCopy={copy} />}
    </div>
);

export const Chip: React.FC<{ children: React.ReactNode; tone?: 'green' | 'blue' | 'red' | 'yellow' | 'grey'; title?: string }> = ({ children, tone = 'grey', title }) => {
    const tones = {
        green: 'bg-hacker-green/10 text-hacker-green border-hacker-green/40',
        blue: 'bg-cyber-blue/10 text-cyber-blue border-cyber-blue/40',
        red: 'bg-hacker-red/10 text-hacker-red border-hacker-red/50',
        yellow: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/40',
        grey: 'bg-hacker-dark text-text-secondary border-hacker-green/20',
    };
    return <span title={title} className={`inline-block text-xs px-2 py-0.5 rounded-sm border ${tones[tone]} break-all`}>{children}</span>;
};

export const sevTone = (s: Severity | string): 'red' | 'yellow' | 'blue' | 'grey' | 'green' =>
    s === 'critical' || s === 'high' ? 'red' : s === 'medium' || s === 'serious' ? 'yellow' : s === 'low' || s === 'moderate' ? 'blue' : 'grey';

export const CopyList: React.FC<{ items: string[]; empty?: string; max?: string; link?: boolean }> = ({ items, empty = 'None observed.', max = 'max-h-56', link }) =>
    items.length ? (
        <ul className={`${max} overflow-y-auto pr-1 text-xs space-y-0.5`}>
            {items.map(i => (
                <li key={i} className="flex items-center justify-between gap-2 border-b border-hacker-green/10 py-0.5">
                    {link ? <a className="truncate text-hacker-green hover:underline" href={i} target="_blank" rel="noopener noreferrer nofollow">{i}</a> : <span className="truncate text-text-primary" title={i}>{i}</span>}
                    <CopyToClipboard textToCopy={i} />
                </li>
            ))}
        </ul>
    ) : <p className="text-text-secondary text-sm">{empty}</p>;

export const Score: React.FC<{ value: number; label: string; grade?: string }> = ({ value, label, grade }) => {
    const tone = value >= 80 ? 'text-hacker-green' : value >= 50 ? 'text-yellow-400' : 'text-hacker-red';
    return (
        <div className="flex flex-col items-center justify-center bg-hacker-dark border border-hacker-green/20 px-3 py-2 min-w-[90px]">
            <span className={`text-3xl font-bold ${tone}`}>{grade ?? value}</span>
            <span className="text-[10px] uppercase tracking-wider text-text-secondary">{label}{grade ? ` · ${value}/100` : ''}</span>
        </div>
    );
};

export const Stat: React.FC<{ label: string; value: React.ReactNode; tone?: string }> = ({ label, value, tone = 'text-cyber-blue' }) => (
    <div className="bg-hacker-dark border border-hacker-green/20 px-3 py-2">
        <div className={`text-xl font-bold ${tone}`}>{value}</div>
        <div className="text-[10px] uppercase tracking-wider text-text-secondary">{label}</div>
    </div>
);
