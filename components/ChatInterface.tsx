import React, { useState, useRef, useEffect } from 'react';
import type { ChatMessage, ExtractionResult } from '../types';

interface ChatInterfaceProps {
    messages: ChatMessage[];
    onSendMessage: (message: string) => void;
    isLoading: boolean;
    result: ExtractionResult | null;
}

const SendIcon = () => (
    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
    </svg>
);

const ChatIcon = () => <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" /></svg>;

const TypingIndicator = () => (
    <div className="flex items-center space-x-2">
        <span className="text-sm text-hacker-green/70">&gt; [Ghostwire Mk.III]: </span>
        <div className="flex space-x-1 items-center h-full">
          <div className="w-2 h-2 bg-hacker-green rounded-full animate-bounce" style={{ animationDelay: '0s' }}></div>
          <div className="w-2 h-2 bg-hacker-green rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
          <div className="w-2 h-2 bg-hacker-green rounded-full animate-bounce" style={{ animationDelay: '0.4s' }}></div>
        </div>
    </div>
);

export const ChatInterface: React.FC<ChatInterfaceProps> = ({ messages, onSendMessage, isLoading, result }) => {
    const [input, setInput] = useState('');
    const [suggestedPrompts, setSuggestedPrompts] = useState<string[]>([]);
    const messagesEndRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (result) {
            const prompts = new Set<string>();
            prompts.add("Summarize the key findings from the report.");
            if (result.advancedRecon?.vulnerabilities && result.advancedRecon.vulnerabilities.length > 0) {
                prompts.add("What are the most critical security vulnerabilities found?");
            }
            if (result.contentLanguage?.sentiment) {
                 prompts.add("What is the overall sentiment of this page?");
            }
             if (result.contentLanguage?.keyTopics && result.contentLanguage.keyTopics.length > 0) {
                prompts.add("What are the key topics discussed?");
            }
            if (result.advancedRecon.technologies && result.advancedRecon.technologies.length > 0) {
                prompts.add("Describe the technology stack used.");
            }
            setSuggestedPrompts(Array.from(prompts).slice(0, 4));
        }
    }, [result]);

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    };

    useEffect(scrollToBottom, [messages, isLoading]);

    const handleSend = () => {
        if (input.trim() && !isLoading) {
            onSendMessage(input.trim());
            setInput('');
        }
    };
    
    const handleSuggestedSend = (prompt: string) => {
        if (!isLoading) {
            onSendMessage(prompt);
        }
    }

    const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
        if (e.key === 'Enter') {
            handleSend();
        }
    };

    return (
        <div className="bg-hacker-dark-2 border border-cyber-blue/30 flex flex-col h-[55vh] max-h-[700px]">
            <div className="px-2 py-1 bg-hacker-dark-2 border-b border-cyber-blue/30 flex items-center space-x-2">
                <div className="text-cyber-blue flex-shrink-0"><ChatIcon /></div>
                <h3 className="font-bold text-base text-hacker-green uppercase tracking-wider truncate" title="// Intelligence Debriefing">// Intelligence Debriefing</h3>
            </div>

            <div className="flex-grow p-2 overflow-y-auto space-y-2">
                {messages.map((msg, index) => (
                    <div key={index} className={`flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'}`}>
                        <div className={`max-w-2xl px-2 py-1 rounded-lg text-sm ${msg.role === 'user' ? 'bg-hacker-green/10' : 'bg-hacker-dark'}`}>
                           {msg.role === 'user' ? (
                               <span className="font-bold text-hacker-green">[user@ghostwire]~$ </span>
                           ) : (
                               <span className="font-bold text-cyber-blue">&gt; [Ghostwire Mk.III]: </span>
                           )}
                           <span className="text-text-primary whitespace-pre-wrap">
                                {msg.content}
                                {isLoading && msg.role === 'model' && index === messages.length - 1 && <span className="blinking-cursor !h-4 !w-2"></span>}
                           </span>
                        </div>
                    </div>
                ))}
                 {isLoading && messages[messages.length-1]?.role !== 'model' && (
                    <div className="items-start">
                        <TypingIndicator />
                    </div>
                )}
                <div ref={messagesEndRef} />
            </div>
            
            {messages.length === 0 && suggestedPrompts.length > 0 && (
                <div className="p-1 border-t border-cyber-blue/30">
                    <p className="text-xs text-text-secondary mb-1">Suggested Prompts:</p>
                    <div className="flex flex-wrap gap-1">
                        {suggestedPrompts.map(prompt => (
                            <button key={prompt} onClick={() => handleSuggestedSend(prompt)} className="text-xs bg-cyber-blue/10 text-cyber-blue px-3 py-1 border border-cyber-blue/50 rounded-full hover:bg-cyber-blue/20 transition-colors">
                                {prompt}
                            </button>
                        ))}
                    </div>
                </div>
            )}

            <div className="p-1 border-t border-cyber-blue/30">
                <div className="flex flex-col sm:flex-row items-stretch gap-1">
                    <input
                        type="text"
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        onKeyDown={handleKeyDown}
                        placeholder={isLoading ? "Awaiting response..." : "Debrief Ghostwire on the report..."}
                        className="w-full bg-hacker-dark p-2 text-hacker-green placeholder-hacker-green/40 focus:outline-none caret-hacker-green border border-hacker-green/30 rounded-sm focus:border-cyber-blue"
                        disabled={isLoading}
                    />
                    <button
                        onClick={handleSend}
                        disabled={isLoading || !input.trim()}
                        className="shrink-0 flex items-center justify-center bg-hacker-green/10 hover:bg-cyber-blue/20 text-hacker-green hover:text-cyber-blue font-bold py-2 px-4 border border-hacker-green hover:border-cyber-blue transition-all duration-300 disabled:bg-hacker-dark-2 disabled:text-hacker-green/40 disabled:border-hacker-green/40 disabled:cursor-not-allowed disabled:shadow-none rounded-sm"
                    >
                        <SendIcon />
                    </button>
                </div>
            </div>
        </div>
    );
};
