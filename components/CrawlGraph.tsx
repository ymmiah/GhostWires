import React, { useMemo } from 'react';
import type { CrawlResult } from '../types';

/** Lightweight radial site graph (no deps): root in the centre, depth rings outward. */
export const CrawlGraph: React.FC<{ crawl: CrawlResult }> = ({ crawl }) => {
    const { nodes, edges } = useMemo(() => {
        const size = 420, c = size / 2;
        const byDepth = new Map<number, string[]>();
        crawl.pages.forEach(p => byDepth.set(p.depth, [...(byDepth.get(p.depth) || []), p.url]));
        const pos = new Map<string, { x: number; y: number; depth: number; status: number }>();
        for (const [depth, urls] of byDepth) {
            const r = depth === 0 ? 0 : 70 + (depth - 1) * 85;
            urls.forEach((u, i) => {
                const a = (i / Math.max(urls.length, 1)) * Math.PI * 2 + depth * 0.4;
                const page = crawl.pages.find(p => p.url === u)!;
                pos.set(u, { x: c + r * Math.cos(a), y: c + r * Math.sin(a), depth, status: page.status });
            });
        }
        return { nodes: [...pos.entries()], edges: crawl.edges.filter(([a, b]) => pos.has(a) && pos.has(b)).map(([a, b]) => [pos.get(a)!, pos.get(b)!]) };
    }, [crawl]);

    return (
        <svg viewBox="0 0 420 420" className="w-full max-w-md mx-auto" role="img" aria-label="Crawl graph">
            {edges.map(([a, b], i) => <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="#00bfff" strokeOpacity={0.25} strokeWidth={1} />)}
            {nodes.map(([url, n]) => (
                <g key={url}>
                    <circle cx={n.x} cy={n.y} r={n.depth === 0 ? 9 : 5} fill={n.status >= 400 || n.status === 0 ? '#ff0033' : n.depth === 0 ? '#00ff41' : '#00bfff'}>
                        <title>{`${url} [${n.status}]`}</title>
                    </circle>
                </g>
            ))}
        </svg>
    );
};
