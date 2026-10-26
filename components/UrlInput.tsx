import React from 'react';

interface UrlInputProps {
    url: string;
    setUrl: (url: string) => void;
    onExtract: () => void;
    isLoading: boolean;
}

const TerminalIcon = () => <span className="text-hacker-green text-lg font-bold">&gt;</span>;
const ExecuteIcon = () => (
    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
    </svg>
);

export const UrlInput: React.FC<UrlInputProps> = ({ url, setUrl, onExtract, isLoading }) => {
    const handleAction = () => {
        if (!isLoading) {
            // Timeout allows state to update and show terminal log before fetch blocks UI
            setTimeout(() => onExtract(), 50);
        }
    }
    
    const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
        if (e.key === 'Enter') {
            handleAction();
        }
    };
    
    return (
        <div className="bg-hacker-dark-2 p-2 flex flex-col sm:flex-row items-stretch gap-2 border-2 border-hacker-green/30 focus-within:border-cyber-blue transition-colors duration-300">
            <div className="flex items-center flex-grow bg-hacker-dark border border-hacker-green/30 rounded-sm">
                 <div className="pl-3 pr-2"><TerminalIcon /></div>
                 <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Enter authorised target URL or domain (e.g. example.com)..."
                    className="w-full bg-transparent p-2 text-hacker-green placeholder-hacker-green/40 focus:outline-none caret-hacker-green"
                    disabled={isLoading}
                    spellCheck="false"
                />
            </div>
            <button
                onClick={handleAction}
                disabled={isLoading}
                className="shrink-0 flex items-center justify-center bg-hacker-green/10 hover:bg-cyber-blue/20 text-hacker-green hover:text-cyber-blue font-bold py-2 px-4 border border-hacker-green hover:border-cyber-blue transition-all duration-300 disabled:bg-hacker-dark-2 disabled:text-hacker-green/40 disabled:border-hacker-green/40 disabled:cursor-not-allowed disabled:shadow-none hover:shadow-glow-blue rounded-sm"
            >
                {isLoading ? (
                    <>
                        <svg className="animate-spin -ml-1 mr-3 h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        <span className="hidden sm:inline">EXECUTING</span>
                    </>
                ) : (
                    <>
                        <ExecuteIcon />
                        <span className="ml-2 hidden sm:inline">EXECUTE</span>
                    </>
                )}
            </button>
        </div>
    );
};
