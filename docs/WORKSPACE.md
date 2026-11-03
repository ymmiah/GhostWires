# Intelligence and owner workspace (4.2)

This is a small extension to GhostWires, with no AiSOC runtime, Kafka, external database, telemetry collector, agent swarm or response automation. AiSOC's investigation-ledger and intelligence patterns informed the design; the implementation here is native TypeScript using Node's built-in SQLite and crypto modules. No upstream triage scorer or suppression rules are imported. Findings remain visible independently of their grouping or review state.

## Intelligence and grouping

CISA KEV is consulted only when a package advisory already supplies an exact CVE ID. GhostWires fetches the canonical CISA JSON catalogue and can fall back to the official `cisagov/kev-data` mirror. The catalogue has a bounded response size, request deadline, schema/count validation, a shared one-hour cache and a five-minute failure backoff. No target names, package inventory, API keys or private evidence are sent to the feed servers. Unknown CVEs are not inferred from banners or product names.

The UI distinguishes current, stale, unavailable and not-requested intelligence. Cached positive entries remain labelled as listed while the snapshot is usable (at most seven days); missing entries become unknown when freshness cannot be established. A fresh absence means only “not listed in this snapshot”. Known exploitation elsewhere does not establish exploitation of this asset. Listed matches move ahead in the review queue without changing deterministic severity or confidence.

Findings are grouped within the exact origin into PHP, database/configuration exposure, dependency advisories and management surface. Groups describe a shared technical surface, not a verified attack chain. They retain every underlying finding and its evidence. The Findings tab adds only a related-surface filter and KEV context.

## Enable saved investigations

Requirements: **Node.js 22.16 or later**, a single application instance, HTTPS in production and a durable, private writable directory. Workspaces are disabled unless `GHOSTWIRES_WORKSPACE_DB` is set. The existing free/ephemeral Render blueprint is left unchanged: do not enable saved workspaces there without provisioning durable storage. No hosting plan, disk or account is created automatically.

For a host installation, create a private directory owned by the application user, then set:

```bash
export GHOSTWIRES_WORKSPACE_DB=/var/lib/ghostwires/workspace.sqlite
export GHOSTWIRES_RETENTION_DAYS=30
npm run build
```

Provision the initial account locally. Replace the example address; use a unique password of at least 14 characters. Read it without terminal echo and send it through stdin, never in command arguments:

```bash
read -rs -p 'New workspace password: ' GW_PASSWORD
printf '%s' "$GW_PASSWORD" | npm run workspace:account -- --workspace main --email owner@example.com --role owner --password-stdin
unset GW_PASSWORD
```

The bundled provisioner is also available in the production image at `dist-server/scripts/workspace-account.cjs`; it runs with Node and requires no development dependencies. Mount the same persistent directory when provisioning and running the server. The image prepares `/data` for the non-root `node` user; mount a private volume there and use `/data/workspace.sqlite`. Existing host bind mounts must have the correct ownership and permissions.

Run the server behind HTTPS with `NODE_ENV=production` and the appropriate `TRUST_PROXY` setting. Production session cookies are Secure, HttpOnly, host-only, SameSite=Strict, use the `__Host-` prefix and expire after eight hours. HTTP development sessions use a separate cookie name. Accounts are provisioned locally rather than through a public signup or invitation interface.

To provision another user, repeat the command with the **same workspace slug** and the desired role:

| Role | Read saved investigations | Save and review | Delete |
|---|---|---|---|
| Owner | Yes | Yes | Yes |
| Analyst | Yes | Yes | No |
| Viewer | Yes | No | No |

Use a different slug for a different tenant. Every evidence/timeline query includes the server-derived tenant identity; the API does not accept client-selected tenants or roles. Email addresses identify one account in one workspace. To revoke an account and all its sessions:

```bash
npm run workspace:account -- --email owner@example.com --revoke
```

Password reset or role/workspace reassignment is an explicit local revoke followed by provisioning a replacement. Historical timeline attribution remains. There are no public password-reset emails or account-management screens in this release.

## Small daily workflow

1. Expand **Workspace** and sign in.
2. Run a fresh DNS-verified owner assessment while signed in.
3. Select **Save current assessment** within 15 minutes.
4. Review its findings and timeline; choose open, in-review, resolved or accepted-risk and optionally add a note.

Resolved and accepted-risk require a reason. These are human review states, not proof of remediation. Evidence snapshots cannot be edited through the API; new assessments are separate snapshots. Notes and state changes append server-authored timestamps and actor attribution. Concurrent edits must match the current investigation version. The owner can explicitly delete an investigation and its timeline.

Saved evidence requires a short-lived HMAC receipt bound to the exact assessment digest, tenant, user and login session. Public assessments, edited snapshots and proofs from other sessions cannot be saved. The digest is checked on read to detect accidental or unauthorised snapshot edits; it is not a public-key signature or protection against a fully compromised host. Receipt material is omitted from ordinary JSON report exports. Changing accounts/signing out clears current report data, saved selections, chat/analysis state and the tab's BYOK key.

## Storage and limits

SQLite is file-backed, uses prepared statements, transactions, foreign keys, WAL and a private database file mode. Passwords use per-account salted scrypt hashes (N=32768, r=8, p=3, with parameters recorded in the hash format). Session tokens are random and only their hashes are stored. State-changing authenticated requests require a per-session CSRF token; JSON and origin checks also protect login. Failed sign-ins are rate-limited, account failures trigger a temporary lockout, and at most two password derivations run concurrently. The scrypt profile follows the [OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

Only the redacted structured assessment and review timeline are saved: not page bodies, full OSINT reports, harvested contacts, raw logs, AI-provider keys or AI conversations. Workspaces are capped at 200 investigations, each with at most 500 findings/512 KiB of evidence and 200 timeline entries. Notes are capped at 2,000 characters. A shared local database is intended for a single application instance, not horizontally scaled hosting or network-mounted SQLite.

Retention defaults to 30 days, configurable from 1 to 90. The expiry is fixed at capture time and does not extend when someone writes a note. Expired records are immediately inaccessible, and logical deletion cascades to their timeline during hourly purges and list/save operations. Backups and storage-level/WAL forensic erasure require a separate operator policy; database files are not application-encrypted. Protect the persistent disk and its backups accordingly.

## Verification

`npm run typecheck`, `npm test`, `npm run build` and `npm run test:smoke` cover KEV freshness/failure paths, grouping, owner evidence receipts, tenant isolation, CSRF, role checks, lockout, session expiry/revocation, concurrent review and persistence across restart. HTTP tests exercise the actual workspace router against SQLite.

Optional browser smoke: install Playwright in a development environment and its Chromium browser, then run `npm run test:browser` after building. It exercises desktop/mobile layouts, sign-in, grouping/KEV display, real save/review APIs, closure reasons, logout clearing, viewer access and tenant switching. Only the scan response is a fixture; it does not scan a live target or exercise live AI/feed calls. Playwright is not a runtime dependency. `GHOSTWIRES_PLAYWRIGHT_MODULE` and `GHOSTWIRES_CHROMIUM_PATH` can select an existing development installation; screenshots are written only when `GHOSTWIRES_QA_OUTPUT` is explicitly set.

References: [AiSOC](https://github.com/beenuar/AiSOC), [AiSOC evidence-ledger design](https://github.com/beenuar/AiSOC/blob/main/docs/architecture/evidence-bundles.md), [official KEV mirror](https://github.com/cisagov/kev-data), [Node SQLite](https://nodejs.org/api/sqlite.html).
