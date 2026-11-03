import { test } from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { AssessmentPanel } from '../components/AssessmentPanel';
import { AssessmentControls } from '../components/AssessmentControls';
import type { SurfaceAssessment } from '../types';

test('legacy report rendering explains missing assessment coverage', () => {
    const html = renderToStaticMarkup(React.createElement(AssessmentPanel));
    assert.match(html, /legacy report/);
    assert.match(html, /Run a new assessment/);
});

test('finding and evidence rendering escapes attacker-controlled markup and retains uncertainty', () => {
    const a: SurfaceAssessment = {
        schemaVersion: '1.0', mode: 'public', generatedAt: '2026-11-03T12:00:00Z', scope: 'https://example.com',
        findings: [{ id: 'fixture', checkId: 'fixture', title: '<script>alert(1)</script>', severity: 'medium', confidence: 'low', status: 'potential-vulnerability', asset: 'https://example.com', observedAt: '2026-11-03T12:00:00Z', evidence: ['<img src=x onerror=alert(1)>'], impact: 'Unknown reachability', remediation: 'Review', verification: 'Recheck', limitations: ['Unverified fixture'], references: ['https://www.php.net/supported-versions.php'] }],
        components: [], coverage: [{ checkId: 'db', label: 'Database permissions', status: 'not-assessed', detail: 'Not inspected from a website URL.' }], limitations: ['Limited coverage'],
        intelligence: { source: 'Fixture', status: 'unavailable', detail: 'Feed unavailable' },
    };
    const html = renderToStaticMarkup(React.createElement(AssessmentPanel, { assessment: a }));
    assert.ok(!html.includes('<script>'));
    assert.ok(!html.includes('<img src=x'));
    assert.match(html, /&lt;script&gt;/);
    assert.match(html, /potential vulnerability/);
    assert.match(html, /not-assessed/);
    assert.match(html, /Feed unavailable/);
});

test('initial controls use public mode without rendering a proof token or uploading inventory', () => {
    const html = renderToStaticMarkup(React.createElement(AssessmentControls, { url: 'https://example.com', disabled: false, onChange: () => { throw new Error('No automatic submission'); } }));
    assert.match(html, /Public surface/);
    assert.match(html, /checked=""/);
    assert.ok(!html.includes('ghostwires-verification='));
    assert.ok(!html.includes('type="file"'));
});
