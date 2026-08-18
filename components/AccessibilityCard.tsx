import React from 'react';
import type { AccessibilityIssue } from '../types';
import { Card } from './Card';

const AccessibilityIcon = () => <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M18.364 5.636l-3.536 3.536m0 5.656l3.536 3.536M9.172 9.172L5.636 5.636m3.536 9.192l-3.536 3.536M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-5 0a4 4 0 11-8 0 4 4 0 018 0z" /></svg>;


const getImpactClass = (impact: AccessibilityIssue['impact']) => {
    switch (impact) {
        case 'critical': return 'bg-hacker-red text-white';
        case 'serious': return 'bg-red-500 text-white';
        case 'moderate': return 'bg-yellow-500 text-hacker-dark';
        case 'minor': return 'bg-hacker-green/40 text-text-primary';
        default: return 'bg-gray-500 text-text-primary';
    }
};

const getImpactBorderClass = (impact: AccessibilityIssue['impact']) => {
    switch (impact) {
        case 'critical': return 'border-hacker-red';
        case 'serious': return 'border-red-500';
        case 'moderate': return 'border-yellow-500';
        case 'minor': return 'border-hacker-green/40';
        default: return 'border-gray-500';
    }
};

export const AccessibilityCard: React.FC<{ issues: AccessibilityIssue[]; score?: number }> = ({ issues, score }) => {
    return (
        <Card title="// Accessibility Audit" icon={<AccessibilityIcon />}>
            {typeof score === 'number' && (
                 <div className="mb-1 pb-1 border-b border-hacker-green/30">
                    <strong className="text-hacker-green">Overall Score:</strong>
                    <span className="ml-2 font-bold text-2xl text-cyber-blue">{score}/100</span>
                 </div>
            )}
            {issues.length > 0 ? (
                <div className="space-y-1 max-h-80 overflow-y-auto pr-2">
                    {issues.map((issue, index) => (
                        <div key={index} className={`bg-hacker-dark p-1 border-l-4 ${getImpactBorderClass(issue.impact)}`}>
                            <div className="flex justify-between items-center">
                                <strong className="text-text-primary capitalize">{issue.impact}</strong>
                                <span className={`px-2 py-0.5 text-xs rounded-full ${getImpactClass(issue.impact)}`}>{issue.impact}</span>
                            </div>
                            <p className="text-text-secondary text-sm mt-1">{issue.description}</p>
                             <p className="text-cyber-blue/70 text-xs mt-1 font-mono truncate" title={issue.element}>
                                Element: {issue.element}
                            </p>
                        </div>
                    ))}
                </div>
            ) : <p className="text-text-secondary">No accessibility issues flagged by AI.</p>}
        </Card>
    );
};