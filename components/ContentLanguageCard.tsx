import React from 'react';
import type { ContentLanguageResult } from '../types';
import { Card } from './Card';

const LanguageIcon = () => <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M3 5h12M9 3v2m1.048 9.5A18.022 18.022 0 016.412 9m6.088 9h7M11 21l5-10-5-10M17 21l5-10-5-10" /></svg>;

const SentimentGauge: React.FC<{ score: number }> = ({ score }) => {
  // Normalize score from [-1, 1] to [0, 100]
  const percentage = (score + 1) * 50;
  const circumference = 2 * Math.PI * 28;
  const offset = circumference - (percentage / 100) * circumference;

  let colorClass = 'text-yellow-500'; // Neutral
  if (percentage > 60) colorClass = 'text-hacker-green'; // Positive
  if (percentage < 40) colorClass = 'text-hacker-red'; // Negative

  return (
    <div className="relative w-24 h-24">
      <svg className="w-full h-full" viewBox="0 0 60 60">
        <circle className="text-hacker-dark-2" strokeWidth="4" stroke="currentColor" fill="transparent" r="28" cx="30" cy="30" />
        <circle
          className={colorClass}
          strokeWidth="4"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          stroke="currentColor"
          fill="transparent"
          r="28"
          cx="30"
          cy="30"
          style={{ transform: 'rotate(-90deg)', transformOrigin: '50% 50%', transition: 'stroke-dashoffset 0.5s ease-out' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
         <span className={`text-2xl font-bold ${colorClass}`}>
            {score.toFixed(2)}
        </span>
        <span className="text-xs text-text-secondary -mt-1">Sentiment</span>
      </div>
    </div>
  );
};

const ReconDataItem: React.FC<{label: string, value: React.ReactNode}> = ({label, value}) => (
    <div>
        <strong className="text-hacker-green">{label}:</strong>
        <div className="text-text-secondary mt-1">{value || 'N/A'}</div>
    </div>
);


export const ContentLanguageCard: React.FC<{ data: ContentLanguageResult }> = ({ data }) => {
    return (
        <Card title="// Content & Language" icon={<LanguageIcon />}>
            <div className="flex flex-col md:flex-row gap-1 items-center">
                <div className="flex-shrink-0">
                    <SentimentGauge score={data.sentiment} />
                </div>
                <div className="flex-grow w-full text-sm space-y-0.5">
                    <ReconDataItem label="Readability" value={data.readabilityScore} />
                    <ReconDataItem label="Language" value={data.detectedLanguage} />
                </div>
            </div>
            <div className="mt-1 pt-1 border-t border-hacker-green/30 text-sm">
                <strong className="text-hacker-green">Key Topics:</strong>
                {(data.keyTopics && data.keyTopics.length > 0) ? (
                    <div className="flex flex-wrap gap-1 mt-1">
                        {data.keyTopics.map((topic, i) => (
                            <span key={i} className="bg-cyber-blue/10 text-cyber-blue text-xs font-medium px-2.5 py-1 rounded-full border border-cyber-blue/50">
                                {topic}
                            </span>
                        ))}
                    </div>
                ) : <p className="text-text-secondary mt-1">No specific topics extracted.</p>}
            </div>
        </Card>
    );
};