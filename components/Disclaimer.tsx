import React from 'react';

export const Disclaimer: React.FC = () => (
    <div className="bg-hacker-dark-2 border-2 border-cyber-blue/30 p-4 text-center text-sm text-text-secondary">
        <h4 className="font-bold text-base text-hacker-green uppercase tracking-widest mb-2">// System Warning //</h4>
        <p className="mb-2">
            This tool performs live analysis of a target URL's HTML content via a generative AI model. Extraction accuracy depends on target site architecture and AI parsing capabilities.
        </p>
        <p>
            The analysis may not capture all data, especially from dynamic, script-heavy sites. This tool is for educational and illustrative purposes. Always verify intelligence from the primary source.
        </p>
    </div>
);