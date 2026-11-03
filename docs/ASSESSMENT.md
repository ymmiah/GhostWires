# GhostWires 4.1: evidence-based surface assessment

This release adds structured HTTP exposure findings to the existing OSINT pipeline. It identifies public evidence and potential package-advisory matches; it does not establish that every vulnerability is absent or exploitable.

## Assessment modes

Public mode inspects the requested page, along with existing DNS, TLS, robots, sitemap, security.txt, CT and Wayback sources. It does not automatically request the owner-only path list. Supplying a URL remains an explicit request to fetch that resource.

Owner mode requires a signed, expiring challenge and a matching DNS TXT record at `_ghostwires.<hostname>`. The token is tied to the exact scheme, hostname and port. It expires after 30 minutes and becomes invalid after a server restart. Every owner assessment rechecks DNS proof. IP-literal targets cannot use owner mode. For a deployment with multiple replicas, requests need instance affinity; tokens are intentionally signed by a process-local key.

After proof, owner mode performs at most five additional GET checks: `/.env`, `/phpinfo.php`, `/phpmyadmin/`, `/adminer.php`, and `/.git/HEAD`. Each response is capped at 32 KiB with a five-second request deadline and at most two redirects within the exact origin. No paths are discovered recursively. It honours available robots rules, skips owner checks if robots policy is unavailable, and skips them when the declared delay exceeds the time budget. Response signatures, rather than HTTP 200 alone, establish observations.

## Findings and coverage

Every finding contains a stable ID, check ID, asset, timestamp, severity, confidence, evidence, impact, remediation, verification steps, limitations and references. Current statuses are `observed-exposure` and `potential-vulnerability`. The engine does not claim verified exploitation.

Checks cover PHP version disclosure and upstream lifecycle, PHP errors and configuration diagnostics, public environment/PHP source disclosure, Git HEAD disclosure, directory indexes, database error signatures and phpMyAdmin/Adminer page titles. Database signatures recognise MySQL/MariaDB, PostgreSQL, SQL Server, Oracle, SQLite, MongoDB, Redis and Elasticsearch. A signature can be quoted content; it does not establish database access or SQL injection. Code and script examples are excluded from the error-signature text, but other quoted content may still require manual review.

Coverage states distinguish `completed`, `partial`, `blocked`, `error` and `not-assessed`. Completed means the named bounded check ran, not that the application is secure. Truncated responses and advisory pagination are partial. Missing version information and hidden database permissions remain unassessed. The PHP lifecycle snapshot was reviewed on 3 November 2026 against https://www.php.net/supported-versions.php. After 90 days it requires manual refresh and does not assert a current end-of-support finding. Vendor backports are not assessed.

## Composer advisories and privacy

Owners can import a `composer.lock` file smaller than 2 MiB. The browser extracts only production package names and exact stable versions; it does not upload the full file, source URLs, credentials, development dependencies or hashes. At most 100 production packages are supported. Pre-release/development versions require manual assessment. Import is atomic: an unsupported package does not silently become a clean result.

The visitor must opt in before package names and versions are submitted. The server queries only GitHub's public reviewed Composer advisory API, in at most five sequential requests, with a 2 MiB response cap, an eight-second deadline, no redirects and a bounded 15-minute memory cache. Neither the target URL nor an API key is sent to GitHub for this lookup. See https://docs.github.com/en/rest/security-advisories/global-advisories.

The matcher confirms package identity and evaluates stable numeric comparator ranges locally. Unsupported syntax remains unknown and makes coverage partial. Withdrawn and unreviewed advisories are excluded. Failed, rate-limited, malformed, truncated or paginated responses do not become a clean bill of health. Potential matches need owner review of deployment accuracy, backports, configuration and reachability. Known-exploitation status is explicitly unknown; CISA KEV is not integrated in this release.

PHP/database runtime CVE feeds and WordPress plugin advisory feeds are not included. Detecting those technologies does not imply advisory coverage for them.

## Networking and resource boundaries

Outbound HTTP uses Node HTTP/HTTPS with a socket lookup pinned to the public addresses validated before each hop. The original hostname remains in the URL for Host/SNI and normal TLS certificate validation. Private/reserved addresses, mixed public/private answers, IPv4-mapped private addresses and IPv6 transition destinations are rejected. URL objects undergo the same protocol, credential and port validation as string inputs. Redirects are revalidated before connecting, and same-origin restrictions are checked before DNS/connection.

Responses have deadlines, compressed and decompressed byte caps, explicit truncation and interruption errors. Scan work is limited to two concurrent recon/crawl jobs and one per initial hostname in each process. This is not a separate worker sandbox: process isolation, cross-replica quotas and network-level egress restrictions remain deployment hardening work. Direct pinned sockets require ordinary outbound network access; HTTP proxy environment variables are not used for target requests. Deployments requiring a proxy need a policy-enforcing proxy transport before enabling scans.

Closing/cancelling the recon request cancels its primary HTTP, sitemap, security.txt and owner-check requests. Existing DNS, TLS, CT and Wayback operations may finish within their own deadlines. They are not falsely reported as completed cancelled checks. No scan history is persisted server-side; JSON exports remain visitor-controlled.

Common credential assignments, credential-bearing connection URLs, known key formats, sensitive URL parameters and cookie/authentication header values are redacted before retaining a recon report. Owner-check findings retain signature descriptions rather than raw configuration or diagnostic bodies. This is defence in depth, not a guarantee of recognising every possible secret format; review exports before sharing them.

## AI interpretation

AI receives the redacted findings, coverage, limitations and advisory metadata. Prompts distinguish untrusted report/page data from instructions and require finding IDs, uncertainty and defensive guidance. Returned per-finding guidance is restricted to existing finding IDs and deduplicated. AI cannot change deterministic severity, status or evidence, and it has no scan execution tools. Prompt instructions do not guarantee factual output; humans must verify generated advice. Live model-provider behaviour requires an available provider key and is separate from deterministic tests.

## Validation and rollout

Run `npm ci`, `npm run typecheck`, `npm test`, `npm run build` and `npm run test:smoke`. Fixtures cover clean and vulnerable responses, false-positive controls, secret redaction, range boundaries, advisory failures, ownership proofs, scope, SSRF, decompression caps, cancellation and concurrency. Production smoke checks boot the compiled server without AI keys and test API rejection paths and static security headers.

Review the feature branch before merging: the existing Render blueprint automatically redeploys from main. Roll back by reverting the feature commit or deploying the previous container tag. Legacy report consumers remain compatible because `assessment` is optional in the shared report type; existing routes and providers remain available.

Follow-on work: isolated scan workers, a signed local collector for PHP/database inventory, runtime and WordPress advisory feeds with explicit coverage/licensing, CISA KEV enrichment, scan comparison, shareable HTML/PDF reports and opt-in monitoring. None of those capabilities is represented as implemented by this release.
