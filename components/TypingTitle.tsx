import React, { useEffect, useState } from 'react';

/** Types the text out once on load, then leaves a thin blinking caret (like MS Word). */
export const TypingTitle: React.FC<{ text: string; speedMs?: number; startDelayMs?: number }> = ({ text, speedMs = 90, startDelayMs = 300 }) => {
    const reduce = typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    const [count, setCount] = useState(reduce ? text.length : 0);

    useEffect(() => {
        if (reduce) return;
        let i = 0;
        let timer: ReturnType<typeof setTimeout>;
        const tick = () => {
            i += 1;
            setCount(i);
            if (i < text.length) timer = setTimeout(tick, speedMs + Math.random() * 60);
        };
        timer = setTimeout(tick, startDelayMs);
        return () => clearTimeout(timer);
    }, [text, speedMs, startDelayMs, reduce]);

    const typing = count < text.length;
    return (
        <span aria-label={text}>
            <span aria-hidden="true">{text.slice(0, count)}</span>
            <span aria-hidden="true" className={`word-caret ${typing ? 'word-caret--solid' : ''}`} />
        </span>
    );
};
