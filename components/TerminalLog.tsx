import React, { useState, useEffect, useRef, useCallback } from 'react';

interface TerminalLogProps {
  messages: string[];
}

const TerminalLine: React.FC<{ text: string, onFinished: () => void }> = ({ text, onFinished }) => {
    const [displayedText, setDisplayedText] = useState('');
    
    useEffect(() => {
        setDisplayedText(''); // Reset on new text
        // Handle empty text case immediately
        if (!text) {
            onFinished();
            return;
        }

        let i = 0;
        const intervalId = setInterval(() => {
            if (i < text.length) {
                // Using substring is safer than appending char by char from a closure
                setDisplayedText(text.substring(0, i + 1));
                i++;
            } else {
                clearInterval(intervalId);
                onFinished();
            }
        }, 20); // Typing speed

        return () => clearInterval(intervalId);
    }, [text, onFinished]);

    return <p className="text-hacker-green whitespace-pre-wrap">&gt; {displayedText}<span className="blinking-cursor !h-4 !w-2"></span></p>;
};

export const TerminalLog: React.FC<TerminalLogProps> = ({ messages }) => {
    const [linesToShow, setLinesToShow] = useState(1);
    const containerRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        setLinesToShow(1); // Reset when messages change
    }, [messages]);
    
    useEffect(() => {
        if (containerRef.current) {
            containerRef.current.scrollTop = containerRef.current.scrollHeight;
        }
    }, [linesToShow, messages]);

    const handleLineFinished = useCallback(() => {
        setLinesToShow(prev => Math.min(prev + 1, messages.length));
    }, [messages.length]);
    
    const finishedLines = messages.slice(0, linesToShow - 1);
    const currentLine = messages[linesToShow - 1];

    return (
        <div 
            ref={containerRef} 
            className="bg-hacker-dark-2 border-2 border-hacker-green/30 p-4 font-mono text-sm h-48 overflow-y-auto"
            aria-live="polite"
        >
            {finishedLines.map((msg, index) => (
                 <p key={index} className="text-hacker-green whitespace-pre-wrap">{msg}</p>
            ))}
            {currentLine && <TerminalLine text={currentLine.replace(/^>\s*/, '')} onFinished={handleLineFinished} />}
        </div>
    );
};
