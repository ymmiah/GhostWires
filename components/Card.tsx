import React from 'react';

export const Card: React.FC<{ title: string; icon: React.ReactNode; children: React.ReactNode; headerActions?: React.ReactNode; bodyClassName?: string; }> = ({ title, icon, children, headerActions, bodyClassName }) => (
    <div className="bg-hacker-dark-2 border border-hacker-green/30 hover:border-cyber-blue/50 transition-colors duration-300 h-full flex flex-col">
        <div className="px-2 py-1 bg-hacker-dark-2 border-b border-hacker-green/30 flex items-center justify-between gap-4">
            <div className="flex items-center space-x-2 min-w-0">
                <div className="text-hacker-green flex-shrink-0">{icon}</div>
                <h3 className="font-bold text-base text-hacker-green uppercase tracking-wider truncate" title={title}>{title}</h3>
            </div>
            {headerActions && <div className="flex-shrink-0">{headerActions}</div>}
        </div>
        <div className={`p-2 flex-grow overflow-auto ${bodyClassName || ''}`}>{children}</div>
    </div>
);
