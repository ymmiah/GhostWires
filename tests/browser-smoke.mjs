// Optional: npm install --no-save playwright && npx playwright install chromium
// Run after the production build. Only the scan response is a fixture; workspace APIs use SQLite.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { WorkspaceStore } from '../server/workspace/store.ts';
import { assessment } from './fixtures/assessment.ts';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.GHOSTWIRES_PLAYWRIGHT_MODULE || 'playwright');
const directory = mkdtempSync(path.join(tmpdir(), 'ghostwires-browser-'));
const filename = path.join(directory, 'workspace.sqlite');
const store = new WorkspaceStore(filename);
const password = 'Browser-fixture-password-42!';
await store.createAccount('alpha', 'owner@example.com', password, 'owner');
await store.createAccount('alpha', 'viewer@example.com', password, 'viewer');
await store.createAccount('beta', 'other@example.com', password, 'owner');
const server = spawn(process.execPath, ['dist-server/server.cjs'], { env: { ...process.env, NODE_ENV: 'development', HOST: '127.0.0.1', PORT: '3420', GHOSTWIRES_BYOK_ONLY: '1', GHOSTWIRES_WORKSPACE_DB: filename }, stdio: ['ignore', 'pipe', 'pipe'] });
let log = ''; server.stdout.on('data', d => { log += d; }); server.stderr.on('data', d => { log += d; });
let browser, page;
try {
    const base = 'http://127.0.0.1:3420';
    let ready = false;
    for (let i = 0; i < 60; i++) { try { ready = (await fetch(`${base}/api/health`)).ok; if (ready) break; } catch {} await new Promise(r => setTimeout(r, 100)); }
    assert.ok(ready, log);
    browser = await chromium.launch({ ...(process.env.GHOSTWIRES_CHROMIUM_PATH ? { executablePath: process.env.GHOSTWIRES_CHROMIUM_PATH } : {}), headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'] });
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    page = await context.newPage(); const errors = []; page.on('pageerror', e => errors.push(e.message));
    await page.goto(base); await page.getByLabel('Auto AI analysis').uncheck();
    const workspace = page.locator('details').filter({ has: page.locator(':scope > summary').filter({ hasText: /^Workspace/ }) }).first();
    await workspace.locator(':scope > summary').click();
    const signIn = async email => {
        await workspace.getByLabel('Email', { exact: true }).fill(email);
        await workspace.getByLabel('Password', { exact: true }).fill(password);
        await workspace.getByRole('button', { name: 'Sign in', exact: true }).click();
        await workspace.getByRole('button', { name: 'Sign out', exact: true }).waitFor();
    };
    await signIn('owner@example.com');
    const cookie = (await context.cookies()).find(c => c.name === 'gw_workspace');
    assert.ok(cookie?.httpOnly);
    const principal = store.session(cookie.value);
    const a = assessment();
    a.threatIntelligence = { source: 'CISA KEV fixture', status: 'current', detail: 'Browser test fixture, not a live feed.' };
    a.findings[0].advisory.knownExploited = true;
    a.findings[0].advisory.kev = { dateAdded: '2026-11-02', requiredAction: 'Apply the fixture vendor fix.', ransomwareUse: 'Unknown' };
    a.groups = [{ id: 'fixture-group', title: 'Dependency advisories', reason: 'Shared origin; no compromise is asserted.', findingIds: ['fixture-finding'] }];
    const report = {
        engine: 'GhostWires Mk.IV v4.2.0', generatedAt: a.generatedAt, durationMs: 10,
        target: { input: 'https://example.com/', url: 'https://example.com/', finalUrl: 'https://example.com/', hostname: 'example.com', registrableDomain: 'example.com', status: 200, contentType: 'text/html', bytes: 10, responseTimeMs: 10, redirectChain: [], resolvedIPs: [] },
        dns: { a: [], aaaa: [], cname: [], mx: [], ns: [], txt: [], caa: [], reverse: {}, emailSecurity: { spf: null, dmarc: null, dmarcPolicy: null, findings: [] }, errors: [], resolver: 'system', saasFootprint: [] },
        tls: { available: false, sans: [] }, headers: { score: 100, grade: 'A', findings: [], disclosure: [], cookies: [], raw: {} }, tech: [], contacts: { emails: [], phones: [], socials: [], addresses: [] },
        meta: { title: 'Fixture website', description: '', keywords: [], lang: 'en', canonical: '', generator: '', robotsMeta: '', og: {}, twitter: {}, headings: { h1: [], h2: [] }, wordCount: 0, textSample: '', jsonLdTypes: [] },
        links: [], images: [], subfolders: [], forms: [], accessibility: { score: 100, issues: [] }, robots: { found: false, disallow: [], allow: [], sitemaps: [] }, sitemap: { found: false, urlCount: 0, sample: [], nestedSitemaps: [] }, securityTxt: { found: false, contact: [], policy: [] }, ct: { enabled: false, subdomains: [], certCount: 0 }, wayback: { enabled: false, available: false }, notes: [], assessment: a, workspaceReceipt: store.receipt(a, principal),
    };
    await page.route('**/api/recon', route => route.fulfill({ json: report }));
    await page.getByRole('button', { name: 'Run assessment' }).click();
    await page.getByRole('tab', { name: 'Findings', exact: true }).waitFor();
    await page.getByRole('tab', { name: 'Findings', exact: true }).click();
    await page.getByText('listed — known exploitation elsewhere', { exact: false }).waitFor();
    await page.getByLabel('Related surface').selectOption('fixture-group');
    await workspace.getByRole('button', { name: 'Save current assessment', exact: true }).click();
    await workspace.getByLabel('Review state', { exact: true }).waitFor();
    await workspace.getByLabel('Review state', { exact: true }).selectOption('resolved');
    await workspace.getByRole('button', { name: 'Save review', exact: true }).click();
    await workspace.getByRole('alert').filter({ hasText: 'Add a reason' }).waitFor();
    await workspace.getByLabel('Review state', { exact: true }).selectOption('in-review');
    await workspace.getByLabel('Review note', { exact: true }).fill('Browser QA review note.');
    await workspace.getByRole('button', { name: 'Save review', exact: true }).click();
    await workspace.getByText('Browser QA review note.', { exact: true }).waitFor();
    if (process.env.GHOSTWIRES_QA_OUTPUT) {
        mkdirSync(process.env.GHOSTWIRES_QA_OUTPUT, { recursive: true });
        await page.screenshot({ path: path.join(process.env.GHOSTWIRES_QA_OUTPUT, 'workspace-desktop.png'), fullPage: true });
    }
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true, 'Mobile page must not overflow horizontally');
    if (process.env.GHOSTWIRES_QA_OUTPUT) await page.screenshot({ path: path.join(process.env.GHOSTWIRES_QA_OUTPUT, 'workspace-mobile.png'), fullPage: true });
    await workspace.getByRole('button', { name: 'Sign out', exact: true }).click();
    await workspace.getByRole('button', { name: 'Sign in', exact: true }).waitFor();
    assert.equal(await page.getByRole('heading', { name: 'Reconnaissance Report', exact: true }).count(), 0, 'Sign-out clears current report evidence');
    await signIn('viewer@example.com');
    await workspace.getByRole('button').filter({ hasText: 'Assessment — example.com' }).click();
    await workspace.getByText('Browser QA review note.', { exact: true }).waitFor();
    assert.equal(await workspace.getByRole('button', { name: 'Save review', exact: true }).count(), 0);
    assert.equal(await workspace.getByRole('button', { name: 'Delete investigation', exact: true }).count(), 0);
    await workspace.getByRole('button', { name: 'Sign out', exact: true }).click();
    await workspace.getByRole('button', { name: 'Sign in', exact: true }).waitFor();
    await signIn('other@example.com');
    await workspace.getByText('No saved investigations.', { exact: true }).waitFor();
    assert.equal(await workspace.getByText('Browser QA review note.', { exact: true }).count(), 0);
    assert.deepEqual(errors, []);
    console.log('Browser smoke passed: sign-in, KEV/grouped findings, real evidence save/review, closure reason, mobile overflow, logout clearing, viewer permissions and tenant isolation. Scan response was a fixture.');
} catch (error) {
    if (page) console.error('Browser state:', (await page.locator('body').innerText()).slice(0, 14000));
    throw error;
} finally {
    await browser?.close(); server.kill();
    await new Promise(resolve => server.once('close', resolve));
    store.close(); rmSync(directory, { recursive: true, force: true });
}
