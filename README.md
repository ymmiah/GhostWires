# 👻 GhostWires Mk.IV

**Passive OSINT reconnaissance for websites — real data, not hallucinations.**

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

No key? The deterministic OSINT pipeline still works fully — only the AI tabs are disabled.

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

**Choosing a provider:** set `AI_PROVIDER=nim|gemini|openrouter|groq`. If unset, GhostWires uses Gemini when `GEMINI_API_KEY` exists, otherwise NIM when `NVIDIA_API_KEY` exists, then OpenRouter, then Groq. You can also switch between any configured provider live from the **AI provider** dropdown in the UI; providers without vision show *"Vision n/a"* and image analysis is disabled gracefully.

### Getting a free NVIDIA NIM key

1. Go to **[build.nvidia.com](https://build.nvidia.com)** and sign in / create a free NVIDIA developer account.
2. Open any model page (e.g. *meta/llama-3.2-11b-vision-instruct*) and click **Get API Key** (or visit your profile → *API Keys*).
3. Copy the key (starts with `nvapi-`) into `.env` as `NVIDIA_API_KEY=nvapi-...`.
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
| `PORT`, `HOST` | Server bind (default `0.0.0.0:3000`) |
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
| POST | `/api/ai/analyze` | `{ report, provider? }` | `AIAnalysis` |
| POST | `/api/ai/vision` | `{ images: string[], pageUrl, provider? }` | descriptions per image |
| POST | `/api/ai/chat` | `{ report, messages, provider? }` | streamed plain text |
| GET | `/api/proxy?url=` | – | SSRF-guarded image proxy (non-images returned as inert text) |

Rate limits (per IP): recon 10/min, crawl 3/min, AI 20/min, proxy 120/min.

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
components/             tabs, cards, crawl graph, chat, terminal log
types.ts                shared types (server + client)
```

## 🧱 Stack

React 18 · Vite 6 · Express 5 · TypeScript · cheerio · `@google/genai` · Tailwind (CDN) · Node built-ins (`dns`, `tls`, `net`, `fetch`).

## Known limitations

- DNS-rebinding between the SSRF check and the socket connect is mitigated (every hop is re-validated) but not fully eliminated; run GhostWires on a machine without access to sensitive internal services if you expose it publicly.
- crt.sh is a free community service and is frequently rate-limited — the UI reports this instead of failing the scan.
- Pages rendered entirely client-side expose less HTML to the passive analysis.

---

**Author:** Yasin Mohammed Miah, Student of BCU, BSc Computing Top-Up (Hons) · For education and authorised security assessment only.
