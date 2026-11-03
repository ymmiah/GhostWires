import * as cheerio from 'cheerio';
import { createHash } from 'node:crypto';
import type { AssessmentCoverage, ObservedComponent, SurfaceFinding, Severity } from '../../types';
import { redactEvidence } from './redact';

export interface PageEvidence { url: string; status: number; headers: Headers; text: string; truncated?: boolean; }
export interface DetectionResult { findings: SurfaceFinding[]; components: ObservedComponent[]; coverage: AssessmentCoverage[]; }
const PHP_SOURCE = 'https://www.php.net/supported-versions.php';
const PHP_REVIEWED_AT = '2026-11-03T00:00:00Z';
// Reviewed against upstream PHP lifecycle information. New branches remain unknown until this table is updated.
const PHP_ENDS: Record<string, string> = { '5.6': '2018-12-31', '7.0': '2019-01-10', '7.1': '2019-12-01', '7.2': '2020-11-30', '7.3': '2021-12-06', '7.4': '2022-11-28', '8.0': '2023-11-26', '8.1': '2025-12-31', '8.2': '2026-12-31', '8.3': '2027-12-31', '8.4': '2028-12-31', '8.5': '2029-12-31' };
export const stableId = (check: string, asset: string) => `${check}-${createHash('sha256').update(asset).digest('hex').slice(0, 12)}`;

export function detectExposures(page: PageEvidence, now: string): DetectionResult {
    const findings: SurfaceFinding[] = [], components: ObservedComponent[] = [], coverage: AssessmentCoverage[] = [];
    const $ = cheerio.load(page.text.slice(0, 600_000));
    $('script,style,noscript,code').remove();
    const visible = $.text().replace(/\s+/g, ' ');
    const textual = /(?:text|json|xml|javascript|x-httpd-php)/i.test(page.headers.get('content-type') || 'text/plain');
    const add = (checkId: string, title: string, severity: Severity, evidence: string[], impact: string, remediation: string, verification: string, limitations: string[] = []) => findings.push({
        id: stableId(checkId, page.url), checkId, title, severity, confidence: page.status >= 400 ? 'high' : 'medium', status: 'observed-exposure',
        asset: page.url, observedAt: now, evidence: evidence.map(redactEvidence), impact, remediation, verification, limitations, references: ['https://owasp.org/www-project-web-security-testing-guide/'],
    });
    const powered = page.headers.get('x-powered-by') || '';
    const php = powered.match(/\bPHP\/(\d+\.\d+(?:\.\d+)?)(?![\d.a-z-])/i);
    if (php) {
        components.push({ name: 'PHP', version: php[1], source: `${page.url} — X-Powered-By`, confidence: 'medium' });
        add('php-version', 'PHP version disclosed in response headers', 'info', [`X-Powered-By: PHP/${php[1]}`], 'Public version information can help an outsider narrow their research.', 'Set expose_php=Off and review proxy/server version disclosure.', 'Request the page again and inspect X-Powered-By.');
        const branch = php[1].split('.').slice(0, 2).join('.');
        const end = PHP_ENDS[branch];
        const stale = Date.parse(now) - Date.parse(PHP_REVIEWED_AT) > 90 * 86400_000;
        coverage.push({ checkId: 'php-lifecycle', label: 'PHP support lifecycle', status: !end || stale ? 'partial' : 'completed', detail: `Upstream lifecycle snapshot reviewed ${PHP_REVIEWED_AT.slice(0, 10)}.${!end ? ' Observed branch is not in this snapshot.' : ''}${stale ? ' Snapshot needs refreshing; current support status requires manual verification.' : ''} Distribution/vendor backports are not assessed.` });
        if (end && Date.parse(now) >= Date.parse(`${end}T23:59:59.999Z`) && !stale) {
            add('php-eol', 'Disclosed PHP branch is past upstream security support', 'high', [`Header claims PHP/${php[1]}; upstream security support ended ${end}.`], 'An unsupported upstream PHP branch may lack security fixes.', 'Confirm the deployed package and vendor support status, then upgrade to a supported PHP release and test application compatibility.', 'Check the actual installed package and its security support contract; rescan after upgrading.', ['The header may be inaccurate.', 'Distribution or commercial vendor backports can change the actual risk.']);
            const f = findings[findings.length - 1]; f.status = 'potential-vulnerability'; f.references = [PHP_SOURCE];
        }
    } else coverage.push({ checkId: 'php-lifecycle', label: 'PHP support lifecycle', status: 'not-assessed', detail: 'No reliable PHP version header observed. A hidden version is not evidence that PHP is absent or supported.' });

    if (textual) {
        const errors: [string, string, RegExp][] = [
            ['MySQL / MariaDB', 'mysql', /SQLSTATE\[HY000\]\s*\[(?:1045|1049|2002|2006)\]|mysqli?_connect\(\):|You have an error in your SQL syntax/i],
            ['PostgreSQL', 'postgresql', /pg_(?:connect|query)\(\):|org\.postgresql\.util\.PSQLException|PostgreSQL.*(?:FATAL|ERROR):/i],
            ['SQL Server', 'sqlserver', /Microsoft (?:SQL Server|SQL Native Client|OLE DB Provider for SQL Server)|SQLSTATE\[42000\].{0,100}\[SQL Server\]/i],
            ['Oracle', 'oracle', /ORA-\d{5}:|OracleException/i],
            ['SQLite', 'sqlite', /SQLite(?:3)?(?:Exception|::)|SQLSTATE\[HY000\].{0,50}no such table/i],
            ['MongoDB', 'mongodb', /MongoServerError:|MongoDB\\Driver\\Exception|MongoNetworkError:/i],
            ['Redis', 'redis', /RedisException:|WRONGTYPE Operation against a key|NOAUTH Authentication required/i],
            ['Elasticsearch', 'elasticsearch', /"type"\s*:\s*"(?:index_not_found_exception|security_exception)"/i],
        ];
        for (const [name, key, pattern] of errors) if (pattern.test(visible)) {
            components.push({ name, source: `${page.url} — public error signature`, confidence: 'medium' });
            add(`database-error-${key}`, `${name} error details are publicly visible`, 'medium', [`Matched ${name} error signature; raw error content is omitted to avoid retaining credentials.`], 'Error output can disclose implementation details useful to an attacker.', 'Return generic public errors; keep detailed diagnostics in access-controlled server logs.', 'Repeat the original request after correcting the error handler; confirm detailed diagnostics are no longer public.', ['A matching string can be quoted documentation or sample content.', 'This does not prove SQL injection, database access or an exposed database port.']);
        }
        if (/SQLSTATE\[[A-Z0-9]{5}\]/.test(visible) && !findings.some(f => f.checkId.startsWith('database-error-'))) add('database-error-unknown', 'Database driver error details are publicly visible', 'medium', ['SQLSTATE diagnostic marker observed; database engine and raw error values omitted.'], 'Driver diagnostics can disclose application internals, but the database engine is not established.', 'Return generic public errors and keep detailed database exceptions in protected server logs.', 'Repeat the original request and confirm that driver diagnostics are no longer public.', ['This does not prove injection, database access or a particular database engine.']);
        if (/(?:Fatal error|Uncaught (?:Error|Exception)|Warning):\s/.test(visible) && /(?:\.php\b|Stack trace:|on line \d+)/i.test(visible)) add('php-error', 'PHP diagnostic details are publicly visible', 'medium', ['PHP error/exception marker and file or stack-trace marker observed; raw diagnostic content omitted.'], 'Diagnostics may reveal server paths and application internals.', 'Disable display_errors in production, enable protected error logging and use a generic error handler.', 'Repeat the request and verify that file paths and stack traces are no longer returned.', ['Quoted examples can resemble real errors; review the response context.']);
        if (/PHP Version\s+\d+\.\d+/i.test(visible) && /(?:phpinfo\(\)|PHP API|Configuration File \(php.ini\) Path)/i.test(visible)) add('phpinfo', 'PHP configuration diagnostics are publicly visible', 'high', ['Matched PHP version and phpinfo configuration markers; configuration values omitted.'], 'Diagnostic output may disclose environment settings, paths and credentials.', 'Remove public phpinfo scripts and restrict diagnostic endpoints to authorised administrators.', 'Request the diagnostic URL and confirm it returns 403/404 without configuration output.');
        const envKeys = page.text.match(/^(?:APP_KEY|APP_ENV|DB_HOST|DB_DATABASE|DB_USERNAME|DB_PASSWORD)\s*=/gm) || [];
        if (!/<html\b/i.test(page.text) && new Set(envKeys).size >= 2) add('environment-file', 'Application environment configuration is publicly readable', 'high', ['Multiple application/database environment assignment names found; all values omitted.'], 'Public configuration may expose database credentials or application secrets.', 'Block web access to environment files, move secrets outside the document root and rotate any exposed credentials.', 'Confirm the file returns 403/404, then verify credential rotation and inspect access logs.');
        if (page.text.includes('<?php') && /(?:define\s*\(\s*['"]DB_|\$(?:db_password|password)\s*=)/i.test(page.text)) add('php-source', 'PHP configuration source appears publicly readable', 'high', ['PHP source opening tag and credential configuration marker observed; source omitted.'], 'PHP source disclosure can reveal credentials and application logic.', 'Correct PHP handler configuration, remove public source backups and rotate exposed secrets.', 'Confirm PHP executes correctly and source/configuration files cannot be downloaded.');
        if (/^ref: refs\/heads\/[\w./-]+\s*$/.test(page.text.trim()) && new URL(page.url).pathname === '/.git/HEAD') add('git-metadata', 'Git repository metadata is publicly readable', 'medium', ['Git HEAD reference format observed; no repository objects were fetched.'], 'Other repository files may also be exposed, potentially including historical secrets.', 'Deny access to .git at the web server and deploy artefacts without repository metadata.', 'Verify /.git/HEAD returns 403/404 and review deployment contents.');
        if (/Index of\s*\//i.test($('title').text()) && /Parent Directory/i.test(visible)) add('directory-index', 'Web directory listing is enabled', 'low', ['Directory-index title and parent-directory navigation observed.'], 'Directory indexes can reveal files that were not intended to be discoverable.', 'Disable autoindex/indexes and explicitly publish required files.', 'Request the directory again and verify listing is disabled.');
        const admins: [string, RegExp][] = [['phpMyAdmin', /<title[^>]*>[^<]*phpMyAdmin/i], ['Adminer', /<title[^>]*>[^<]*Adminer/i]];
        for (const [name, marker] of admins) if (marker.test(page.text)) {
            components.push({ name, source: `${page.url} — page title`, confidence: 'medium' });
            add(`admin-${name.toLowerCase()}`, `${name} interface is publicly reachable`, 'low', [`${name} title marker observed. Authentication was not attempted.`], 'A public database administration interface increases the exposed management surface.', 'Restrict access using a VPN or an authenticated gateway, enforce MFA where supported and keep the tool updated.', 'Confirm unauthorised external requests cannot reach the administration interface.', ['A reachable login page does not establish unauthorised database access.']);
        }
    }
    coverage.push({ checkId: 'response-exposure', label: 'Response disclosure checks', status: page.truncated ? 'partial' : textual ? 'completed' : 'not-assessed', detail: page.truncated ? 'Response exceeded the size cap; only the bounded prefix was inspected.' : textual ? 'Inspected this response for PHP, database, configuration and diagnostic signatures. No payloads were submitted.' : 'Non-text response; content signatures were not inspected.' });
    return { findings, components, coverage };
}
