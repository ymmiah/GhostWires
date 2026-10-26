# 👻 GhostWires Mk.IV

[![CI](https://github.com/ymmiah/GhostWires/actions/workflows/ci.yml/badge.svg)](https://github.com/ymmiah/GhostWires/actions/workflows/ci.yml)
[![Docker image](https://github.com/ymmiah/GhostWires/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/ymmiah/GhostWires/pkgs/container/ghostwires)
[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/ymmiah/GhostWires)

**Passive OSINT reconnaissance for websites — real data, not hallucinations. Bring your own AI key; it's wiped when you close the tab.**

GhostWires Mk.IV runs a deterministic, server-side OSINT pipeline against a public website (DNS, TLS, HTTP headers, technology fingerprint, public contacts, robots/sitemap/security.txt, Certificate Transparency and the Wayback Machine) and then hands those **verified facts** to an AI model of your choice — **NVIDIA NIM (free)**, Google Gemini, OpenRouter or Groq — for narrative analysis, image description and a grounded debrief chat.

> Built by **Yasin Mohammed Miah, Student of BCU, BSc Computing Top-Up (Hons)**.

---

## ⚠️ Rules of engagement

- **Authorised targets only.** Scan only sites you own or have written permission to assess. You are responsible for complying with the Computer Misuse Act 1990, UK GDPR / GDPR and the target's terms of service.
- **Passive & public data only.** No exploitation, brute forcing, credential testing, port scanning or vulnerability probing. GhostWires reads what any browser or resolver can see.
- **Polite by design.** The crawler honours `robots.txt` (incl. `Crawl-delay`), waits ≥ 750 ms between requests, is capped at 25 pages, and every API route is rate-limited.
- **SSRF-guarded.** Private, loopback, link-local, CGNAT, multicast and cloud-metadata addresses (e.g. `169.254.169.254`) are blocked on every redirect hop; only ports 80/443/8080/8443 are allowed.
- **Contact data is personal data.** Minimise, protect and delete it when you're done. AI output is generated from collected facts but can still be wrong — verify against the source.

---

## 🔑 Bring your own key (BYOK) — wiped when you close the tab

Hosted GhostWires needs **no server-side API key**. Each visitor clicks **🔑 Add API key**, picks a provider (NVIDIA NIM, Gemini, OpenRouter or Groq) and pastes their own key.

How the key is protected:

| Where | What happens |
|---|---|
| Browser storage | Kept only in React memory + **`sessionStorage`** (scoped to that one tab). Never `localStorage`, cookies, IndexedDB or the URL. |
| Tab/window close, reload, navigate away | `pagehide` + `beforeunload` handlers **wipe the key** from sessionStorage and memory. The browser also destroys sessionStorage when the tab closes. |
| Manual / idle | **Forget key** button wipes it instantly; it also auto-wipes after **30 minutes** of inactivity. |
| On the wire | Sent **only** on `/api/ai/*` requests, in the `X-GhostWires-API-Key` header (+ `X-GhostWires-Provider`), to the same origin over HTTPS. Recon and crawl requests never carry it. |
| On the server | Used for that single request to call the provider, then dropped. **Never** logged, written to disk, put in `process.env`, cached, or returned in a response; provider error messages are redacted. AI responses are `Cache-Control: no-store`. |
| In the page | Masked input (password field, password-manager autofill disabled), never echoed to the terminal log or report export. A strict **Content-Security-Policy** (`script-src 'self'`, Tailwind compiled at build time — no CDN scripts) stops third-party JavaScript from reading it. |

> ⚠️ While the tab is open, anyone with access to it can see the key in DevTools (Network tab / sessionStorage) — that is inherent to any BYOK web app. Use a dedicated, low-quota key and close the tab when finished.

Self-hosters can still put keys in `.env`; set `GHOSTWIRES_BYOK_ONLY=1` (the default in the Docker image and Render blueprint) to ignore server keys entirely on a shared deployment.

---

## ☁️ Deploy

GitHub Pages can only host static files, so GhostWires (an Express API + UI) is deployed as a container built by GitHub Actions.

**1 — Render (free, one click).** Click **Deploy to Render** above (or Render → *New → Blueprint* → pick `ymmiah/GhostWires`). `render.yaml` builds the `Dockerfile`, runs it BYOK-only with `TRUST_PROXY=1`, health-checks `/api/health` and redeploys on every push to `main`. No secrets to set.

**2 — Docker (any host / your PC).** Every push to `main` publishes an image to GitHub Container Registry:

```bash
docker run --rm -p 3000:3000 ghcr.io/ymmiah/ghostwires:latest
# open http://localhost:3000 and add your own key
```

Tags: `latest`, `sha-<short>` and `v*` release tags. The image contains **no** API keys or `.env`, runs as the non-root `node` user and has a health check.

**3 — From source:** see *Quick start* below.

CI (`.github/workflows/ci.yml`) type-checks, builds, boots the server without any keys and asserts the health endpoint and SSRF guard on every push and pull request.

---

## ✨ What's new in Mk.IV (vs Mk.III)

| Area | Mk.III | Mk.IV |
|---|---|---|
| Recon data | Gemini *guessed* IPs, DNS, WHOIS, CVEs from HTML | Real data from `dns/promises`, `tls`, HTTP, crt.sh, Wayback |
| API keys | Injected into the browser bundle by Vite | **Server-side only** — never shipped to the client |
| Fetching | Public CORS proxies (leak targets to third parties) | Hardened server fetch: SSRF guard, redirect re-validation, timeouts, size caps |
| AI | Gemini only | Pluggable: **NVIDIA NIM**, Gemini, OpenRouter, Groq |
| Crawl | AI-summarised each page | Deterministic BFS crawl + radial site graph, robots-aware |
| Prod build | `app.get("*")` crashed on Express 5; server bundle exposed under `dist/` | Fixed Express 5 routing; server bundle in `dist-server/` |

### OSINT modules

| Module | Source | Output |
|---|---|---|
| Target normalisation | URL parser + SSRF guard | final URL, redirect chain, resolved IPs, timing |
| DNS intel | Node `dns/promises` (auto DNS-over-HTTPS fallback) | A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, PTR |
| Email security | DNS TXT + `_dmarc` | SPF/DMARC parsing & policy findings |
| SaaS footprint | TXT verification tokens + SPF includes | e.g. Microsoft 365, Google Workspace, Salesforce, SendGrid… |
| TLS certificate | single `tls.connect` handshake | subject, issuer, validity/days left, SANs, protocol, cipher, SHA-256, trust |
| Security headers | response headers | graded audit (HSTS, CSP, XFO, XCTO, Referrer, Permissions, COOP/CORP/COEP), info disclosure, cookie flags |
| Tech fingerprint | ~75 signatures over HTML, scripts, headers, cookies | CMS, frameworks, analytics, CDN/WAF, servers — **each with evidence** |
| Contact harvest | `mailto:`/`tel:`, text (incl. `[at]`/`[dot]`), JSON-LD `sameAs`/`email`/`telephone`/`address`, `<address>` | deduplicated emails, phones, social profiles, addresses |
| Content & SEO | HTML meta | title, description, canonical, OG/Twitter cards, headings, JSON-LD types, links, images, forms |
| Accessibility | static WCAG-inspired heuristics | score + issues (alt text, labels, lang, landmarks, zoom…) |
| robots.txt / sitemap | origin | disallowed paths, declared sitemaps, URL counts |
| security.txt | `/.well-known/security.txt` | contact, policy, expiry (RFC 9116) |
| Certificate Transparency | [crt.sh](https://crt.sh) (cached 1 h, throttled) | subdomains seen in public CT logs |
| Wayback Machine | archive.org availability + CDX APIs | first seen, latest snapshot, months with captures |
| Polite crawler | same-host BFS | pages, status, titles, emails per page, radial graph |
| AI analysis | your chosen LLM, fed **only verified facts** | summary, sentiment, readability, topics, entities, SEO/a11y/security narratives, recommendations |
| AI vision | Gemini or NIM vision model | one-sentence description of up to 6 images |
| Debrief chat | streaming, grounded on the report | Q&A that refuses to invent facts |

---

## 🚀 Quick start

Requirements: **Node.js ≥ 20.12**.

```bash
git clone https://github.com/ymmiah/GhostWires.git
cd GhostWires
npm install
cp .env.example .env        # add NVIDIA_API_KEY and/or GEMINI_API_KEY
npm run dev                 # Express API + Vite UI on http://localhost:3000
```

Or pass keys inline:

```bash
NVIDIA_API_KEY=nvapi-... npm run dev
GEMINI_API_KEY=...       npm run dev
```

No server key? That's fine — click **🔑 Add API key** in the UI (BYOK), or skip AI entirely: the deterministic OSINT pipeline works without any key.

### Production

```bash
npm run build     # vite → dist/, server → dist-server/server.cjs
npm start         # serves the built UI + API on $PORT (default 3000)
```

### Health check

```bash
curl http://localhost:3000/api/health
# {"status":"ok","system":"GhostWires Mk.IV OSINT Reconnaissance Server","version":"4.0.0","aiProvider":"nim",...}
```

---

## 🤖 AI providers (free options)

| Provider | Env key | Default model | Vision | Notes |
|---|---|---|---|---|
| **NVIDIA NIM** | `NVIDIA_API_KEY` | `meta/llama-3.2-11b-vision-instruct` | ✅ | Free developer credits; OpenAI-compatible API at `https://integrate.api.nvidia.com/v1`. Verified for text, JSON and vision. |
| Google Gemini | `GEMINI_API_KEY` (or `API_KEY`) | `gemini-2.5-flash` | ✅ | Free tier via Google AI Studio. |
| OpenRouter | `OPENROUTER_API_KEY` | `google/gemma-4-31b-it:free` | ❌ | Any `:free` model works — set `OPENROUTER_MODEL`. |
| Groq | `GROQ_API_KEY` | `llama-3.3-70b-versatile` | ❌ | Very fast free tier. |

**Choosing a provider:** visitors pick one in the 🔑 dialog (BYOK keys always win). For self-hosted server keys set `AI_PROVIDER=nim|gemini|openrouter|groq`; if unset, GhostWires uses Gemini when `GEMINI_API_KEY` exists, otherwise NIM when `NVIDIA_API_KEY` exists, then OpenRouter, then Groq. Providers without vision show *"Vision n/a"* and image analysis is disabled gracefully.

### Getting a free NVIDIA NIM key

1. Go to **[build.nvidia.com](https://build.nvidia.com)** and sign in / create a free NVIDIA developer account.
2. Open any model page (e.g. *meta/llama-3.2-11b-vision-instruct*) and click **Get API Key** (or visit your profile → *API Keys*).
3. Paste the key (starts with `nvapi-`) into the **🔑 Add API key** dialog — or, when self-hosting, put it in `.env` as `NVIDIA_API_KEY=nvapi-...`.
4. Optional: pick another hosted model with `NIM_MODEL=` (e.g. `openai/gpt-oss-20b` for stronger reasoning; slower) and `NIM_VISION_MODEL=`.

Free endpoints can queue under load — Mk.IV waits up to `AI_TIMEOUT_MS` (default 180 s) and the UI shows progress.

---

## ⚙️ Environment variables

See [`.env.example`](.env.example). Highlights:

| Variable | Purpose |
|---|---|
| `AI_PROVIDER` | `nim` \| `gemini` \| `openrouter` \| `groq` |
| `NVIDIA_API_KEY`, `NIM_MODEL`, `NIM_VISION_MODEL`, `NIM_BASE_URL` | NVIDIA NIM |
| `GEMINI_API_KEY` / `API_KEY`, `GEMINI_MODEL` | Google Gemini |
| `OPENROUTER_API_KEY`, `OPENROUTER_MODEL`, `GROQ_API_KEY`, `GROQ_MODEL` | Optional free paths |
| `GHOSTWIRES_BYOK_ONLY=1` | Ignore all server keys; visitors must bring their own (default in Docker/Render) |
| `TRUST_PROXY` | Set to `1` behind Render/Fly/NGINX so rate limits use the real client IP |
| `PORT`, `HOST` | Server bind (default `0.0.0.0:3000`; Render injects `PORT`) |
| `DNS_MODE=doh`, `DNS_SERVERS`, `DOH_URL` | DNS resolution behaviour |
| `GHOSTWIRES_ALLOW_FAKEIP=1` | Only for local VPN/TUN "fake-ip" setups that answer DNS with `198.18.0.0/15`. Never enable on a shared server. |

---

## 🔌 API

| Method | Route | Body | Returns |
|---|---|---|---|
| GET | `/api/health` | – | status, version, active AI provider |
| GET | `/api/providers` | – | configured providers, models, vision support |
| POST | `/api/recon` | `{ url, ct?: true, wayback?: true }` | `ReconReport` (see `types.ts`) |
| POST | `/api/crawl` | `{ url, maxPages?: 12 }` | `CrawlResult` |
| POST | `/api/ai/verify` | – (key in header) | checks a BYOK key with a tiny completion (≤ 20 s) |
| POST | `/api/ai/analyze` | `{ report, provider? }` | `AIAnalysis` |
| POST | `/api/ai/vision` | `{ images: string[], pageUrl, provider? }` | descriptions per image |
| POST | `/api/ai/chat` | `{ report, messages, provider? }` | streamed plain text |
| GET | `/api/proxy?url=` | – | SSRF-guarded image proxy (non-images returned as inert text) |

All `/api/ai/*` routes accept the BYOK headers `X-GhostWires-API-Key` and `X-GhostWires-Provider`. Rate limits (per IP): recon 10/min, crawl 3/min, AI 20/min, key verify 10/min, proxy 120/min.

---

## 🗂️ Project layout

```
server.ts               Express app, routes, Vite middleware
server/
  env.ts                .env loader (Node built-in)
  net.ts                SSRF guard, safeFetch (manual redirects, caps), politeness
  dnsIntel.ts           DNS + SPF/DMARC + SaaS footprint (+ DoH fallback)
  tlsIntel.ts           TLS handshake certificate summary
  headersAudit.ts       security header grading, disclosure, cookies
  fingerprint.ts        technology signatures
  htmlIntel.ts          meta, links, images, forms, contacts, a11y (cheerio)
  surfaceIntel.ts       robots, sitemap, security.txt, crt.sh, Wayback
  recon.ts              pipeline orchestrator + polite crawler
  rateLimit.ts          in-memory limiter
  ai/providers.ts       Gemini + OpenAI-compatible (NIM / OpenRouter / Groq)
  ai/intel.ts           fact digest, analysis, vision, grounded chat
App.tsx, api.ts         React UI + API client
keyVault.ts             BYOK vault: sessionStorage + memory, wipe on close/idle/forget
components/KeyModal.tsx masked BYOK dialog with key verification
Dockerfile, render.yaml container image + Render blueprint
.github/workflows/      CI (typecheck/build/smoke) + GHCR image publish
components/             tabs, cards, crawl graph, chat, terminal log
types.ts                shared types (server + client)
```

## 🧱 Stack

React 18 · Vite 6 · Express 5 · TypeScript · cheerio · `@google/genai` · Tailwind CSS 3 (compiled, no CDN) · Node built-ins (`dns`, `tls`, `net`, `fetch`).

## Known limitations

- DNS-rebinding between the SSRF check and the socket connect is mitigated (every hop is re-validated) but not fully eliminated; run GhostWires on a machine without access to sensitive internal services if you expose it publicly.
- crt.sh is a free community service and is frequently rate-limited — the UI reports this instead of failing the scan.
- Pages rendered entirely client-side expose less HTML to the passive analysis.

---

**Author:** Yasin Mohammed Miah, Student of BCU, BSc Computing Top-Up (Hons) · For education and authorised security assessment only.
