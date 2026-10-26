import React, { useEffect, useRef } from 'react';

export const TerminalLog: React.FC<{ messages: string[]; active?: boolean }> = ({ messages, active }) => {
    const ref = useRef<HTMLDivElement>(null);
    useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [messages]);
    return (
        <div ref={ref} className="bg-hacker-dark-2 border-2 border-hacker-green/30 p-3 font-mono text-xs sm:text-sm h-44 overflow-y-auto" aria-live="polite">
            {messages.map((m, i) => (
                <p key={i} className={`whitespace-pre-wrap ${/ERROR|FAILED|blocked/i.test(m) ? 'text-hacker-red' : /OK|COMPLETE|online/i.test(m) ? 'text-hacker-green' : 'text-hacker-green/80'} ${i === messages.length - 1 ? 'animate-fade-in' : ''}`}>{m}</p>
            ))}
            {active && <span className="blinking-cursor !h-4 !w-2" />}
        </div>
    );
};
