<div align="center">

# ⚡ GHOSTWIRE Mk.III
### Autonomous Web Intelligence & High-Fidelity OSINT Reconnaissance Framework

[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue.svg?style=flat-square&logo=typescript)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-18.2-61DAFB.svg?style=flat-square&logo=react)](https://reactjs.org/)
[![Vite](https://img.shields.io/badge/Vite-6.2-646CFF.svg?style=flat-square&logo=vite)](https://vitejs.dev/)
[![Tailwind CSS](https://img.shields.io/badge/TailwindCSS-3.4-38B2AC.svg?style=flat-square&logo=tailwind-css)](https://tailwindcss.com/)
[![Gemini 2.5 Flash](https://img.shields.io/badge/AI_Engine-Gemini_2.5_Flash-8E75B2.svg?style=flat-square&logo=google)](https://ai.google.dev/)
[![Architecture](https://img.shields.io/badge/Architecture-Full--Stack_Express_%2B_Vite-green.svg?style=flat-square)](https://expressjs.com/)

<p align="center">
  <b>An enterprise-grade, full-stack intelligence gathering platform engineered for automated digital reconnaissance, threat modeling, technological stack fingerprinting, and linguistic telemetry.</b>
</p>

---

</div>

## 📑 Table of Contents

- [1. Executive System Overview](#1-executive-system-overview)
- [2. System Architecture & Network Topology](#2-system-architecture--network-topology)
- [3. Core Intelligence Modules](#3-core-intelligence-modules)
  - [3.1 Resilient Direct Server Proxy & Failover Matrix](#31-resilient-direct-server-proxy--failover-matrix)
  - [3.2 Infrastructure & Security Fingerprinting](#32-infrastructure--security-fingerprinting)
  - [3.3 Open-Source Intelligence (OSINT) & Contact Harvester](#33-open-source-intelligence-osint--contact-harvester)
  - [3.4 NLP Linguistic Analysis & Sentiment Telemetry](#34-nlp-linguistic-analysis--sentiment-telemetry)
  - [3.5 Accessibility (WCAG / A11y) & SEO Audit Engine](#35-accessibility-wcag--a11y--seo-audit-engine)
  - [3.6 Vision Subroutine (Contextual Multimodal Media Analysis)](#36-vision-subroutine-contextual-multimodal-media-analysis)
  - [3.7 Deep Site Crawler & Recursive Link Graph](#37-deep-site-crawler--recursive-link-graph)
  - [3.8 Intelligence Debriefing (Grounded Tactical AI Analyst)](#38-intelligence-debriefing-grounded-tactical-ai-analyst)
- [4. API Specification & Endpoints](#4-api-specification--endpoints)
- [5. Technology Stack & Dependencies](#5-technology-stack--dependencies)
- [6. Deployment, Build & Production Runtime](#6-deployment-build--production-runtime)
- [7. Directory Structure](#7-directory-structure)
- [8. Security & Ethical Operations Notice](#8-security--ethical-operations-notice)

---

## 1. Executive System Overview

**Ghostwire Mk.III** addresses the core challenge of modern web reconnaissance: client-heavy Single Page Applications (SPAs), aggressive CORS boundaries, dynamic DOM hydration, and multi-vector data extraction.

By coupling a **dedicated Node.js server-side direct proxy** with **Google's Gemini 2.5 Flash LLM**, Ghostwire bypasses browser security constraints, executes deep DOM traversal, extracts structured threat intelligence, and produces verifiable dossiers in milliseconds.

```
+-----------------------------------------------------------------------------------+
|                              GHOSTWIRE MK.III PIPELINE                            |
+-----------------------------------------------------------------------------------+
| [ Target URL ]                                                                    |
|        │                                                                          |
|        ▼                                                                          |
| [ Ingress Protocol Normalizer ] (Protocol auto-resolution, URI sanitization)      |
|        │                                                                          |
|        ▼                                                                          |
| [ Multi-Tier Fetch Engine ] ──► Tier 1: Express Direct Server Proxy (/api/proxy)  |
|                                ──► Tier 2: AllOrigins JSON Gateway                |
|                                ──► Tier 3: CorsProxy.io Fallback Stream           |
|                                ──► Tier 4: CodeTabs Failover                      |
|        │                                                                          |
|        ▼                                                                          |
| [ Fully Hydrated DOM Stream ] (Raw HTML + Structured Assets)                      |
|        │                                                                          |
|        ▼                                                                          |
| [ Gemini 2.5 Flash Engine ] ──► Advanced Infrastructure Recon (WAF, CVE, Stack)   |
|                              ──► OSINT Harvester (Emails, Phones, Executives)     |
|                              ──► Linguistic Telemetry (Sentiment, Readability)    |
|                              ──► A11y & SEO Graph Auditing                        |
|        │                                                                          |
|        ▼                                                                          |
| [ Tactical Command UI & Debriefing Interface ] (Real-Time Terminal, Visualizer)   |
+-----------------------------------------------------------------------------------+
```

---

## 2. System Architecture & Network Topology

Ghostwire Mk.III operates as a unified **Full-Stack Application** combining an Express server host with a reactive Vite/React frontend.

### Network Topology & Proxy Isolation
```
                     +---------------------------------------+
                     |            Client Browser             |
                     |  (React 18 + Tailwind Tactical UI)    |
                     +-------------------+-------------------+
                                         |
                       Fetch Request to Internal Endpoints
                                         |
                                         ▼
                     +---------------------------------------+
                     |         Node.js Express Server        |
                     |             (Port: 3000)              |
                     +-------------------+-------------------+
                                         |
                      Direct Server Fetch (No Browser CORS)
                      + Custom User-Agent & Abort Signals
                                         |
                                         ▼
                     +---------------------------------------+
                     |          Target Remote Host           |
                     |      (https://target-domain.com)      |
                     +---------------------------------------+
```

1. **Zero Browser CORS Failures**: Browser requests are dispatched to the local `/api/proxy` endpoint. The Node server makes direct outbound HTTP/HTTPS calls using Node.js native `fetch` with realistic browser headers (`User-Agent`, `Accept-Language`, `Sec-Fetch-*`), eliminating browser CORS errors and Cloud Run iframe sandbox blocks.
2. **Deterministic Resilience**: If a target blocks direct datacenter IP ingress, the system gracefully falls back across three secondary proxy gateways (`AllOrigins`, `CorsProxy`, `CodeTabs`).

---

## 3. Core Intelligence Modules

### 3.1 Resilient Direct Server Proxy & Failover Matrix
- **Server Route**: `GET /api/proxy?url=<TARGET_URL>`
- **Features**:
  - Outbound timeout protection via `AbortController` (20-second timeout ceiling).
  - Multi-mime type streaming (HTML text mode vs. binary image streaming mode).
  - Custom user-agent rotation mimicking Chrome/Safari desktop environments.
  - Automatic redirect resolution and header propagation.

### 3.2 Infrastructure & Security Fingerprinting
- **Hosting & Network**: Server IP resolution, geographic location (City, Country), hosting platform provider.
- **WAF & Security Perimeters**: Web Application Firewall detection (Cloudflare, AWS WAF, Akamai) and threat notes.
- **CMS & Theme Forensics**: CMS theme identification (WordPress, Shopify, Drupal) and active plugins.
- **Heuristic CVE Vulnerability Engine**: Automated mapping of discovered software components to known Common Vulnerabilities and Exposures (CVEs) with severity levels:
  $$\text{Severity} \in \{\text{Critical}, \text{High}, \text{Medium}, \text{Low}, \text{Informational}\}$$

### 3.3 Open-Source Intelligence (OSINT) & Contact Harvester
- **Communication Vectors**: Regex and semantic extraction of emails, customer service hotlines, direct phone numbers, and physical mailing addresses.
- **Leadership & Personnel Identification**: Maps named individuals, executive officers, and their organizational titles.
- **Social Graph Mapping**: Consolidated registry of GitHub, LinkedIn, Twitter/X, and Facebook footprints.

### 3.4 NLP Linguistic Analysis & Sentiment Telemetry
- **Dynamic Sentiment Gauge**: Normalized circular radial indicator rendering sentiment polarity:
  $$\text{Sentiment Score} \in [-1.00 \text{ (Negative)}, +1.00 \text{ (Positive)}]$$
- **Readability Index**: Automated grade-level reading complexity calculation (e.g., *College Level*, *8th Grade*).
- **Language Detection & Topic Clusters**: Primary dialect detection alongside semantic topic badges.

### 3.5 Accessibility (WCAG / A11y) & SEO Audit Engine
- **A11y Compliance Score**: Normalized 0–100 compliance ranking based on DOM semantic structure, contrast, and missing ARIA properties.
- **Targeted Element Remediation**: CSS selector mapping for each reported accessibility issue.
- **SEO & Social Graph**: Title tag analysis, H1 hierarchy audit, word count metrics, and OpenGraph/Twitter Card asset inspection.

### 3.6 Vision Subroutine (Contextual Multimodal Media Analysis)
- **Secondary Image Extraction Pass**: Analyzes discovered media assets (`<img>` tags) in context with their surrounding DOM markup.
- **AI-Powered Visual Synthesis**: Generates detailed, natural-language summaries for every visual asset.

### 3.7 Deep Site Crawler & Recursive Link Graph
- **Internal Link Manifest**: Automatically compiles unique internal links on the scanned domain.
- **Batch Intelligence Crawl**: Traverses internal sub-pages in sequence, summarizing child page content into the master dossier.

### 3.8 Intelligence Debriefing (Grounded Tactical AI Analyst)
- **Grounded Chat Engine**: An interactive debriefing terminal (`ChatInterface`) powered by Gemini.
- **Anti-Hallucination Guardrails**: Strictly bounded to the JSON reconnaissance report of the target URL.
- **Suggested Tactical Queries**: Pre-computed query prompts for instant investigative pivots.

---

## 4. API Specification & Endpoints

| Method | Endpoint | Description | Query Parameters / Payload |
|---|---|---|---|
| `GET` | `/api/health` | Service health status, version & runtime state | None |
| `GET` | `/api/proxy` | Server-side direct proxy for HTML content | `url` (required, string) |
| `GET` | `/api/proxy` | Binary image proxy mode | `url` (required, string), `type=image` |

### Sample Proxy Response Header Metrics:
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Access-Control-Allow-Origin: *
X-Ghostwire-Status: 200
X-Ghostwire-Final-URL: https://target.example.com
```

---

## 5. Technology Stack & Dependencies

```json
{
  "runtime": "Node.js (v18+ / v22+)",
  "language": "TypeScript 5.8.2",
  "frontend": {
    "framework": "React 18.2.0",
    "styling": "Tailwind CSS 3.4",
    "icons": "Lucide / Inline Optimized SVGs",
    "tooling": "Vite 6.2.0"
  },
  "backend": {
    "server": "Express 4.21.2",
    "typescript_runner": "tsx",
    "bundler": "esbuild 0.25.0"
  },
  "ai_foundation": {
    "sdk": "@google/genai (^1.8.0)",
    "primary_model": "gemini-2.5-flash"
  }
}
```

---

## 6. Deployment, Build & Production Runtime

### Development Mode
Runs the hybrid Express server with integrated Vite middleware:
```bash
# Install dependencies
npm install

# Launch Full-Stack Dev Server on Port 3000
npm run dev
```

### Production Build & Launch
Complies with single-artifact containerization standards:
```bash
# 1. Compiles Vite static assets to dist/
# 2. Bundles server.ts into self-contained CommonJS artifact (dist/server.cjs)
npm run build

# 3. Boots production server
npm run start
```

---

## 7. Directory Structure

```
.
├── components/
│   ├── AccessibilityCard.tsx     # WCAG A11y scoring & issue impact cards
│   ├── Card.tsx                  # Reusable tactical terminal UI card container
│   ├── ChatInterface.tsx         # Intelligence Debriefing AI chat interface
│   ├── ContentLanguageCard.tsx   # SVG Sentiment Gauge & linguistic metrics
│   ├── CopyToClipboard.tsx       # Rapid one-click clipboard extraction utility
│   ├── Disclaimer.tsx            # Legal, compliance & ethical usage notice
│   ├── LoadingSpinner.tsx        # High-visibility radar loading component
│   ├── ResultsDisplay.tsx        # Master reconnaissance dossier dashboard
│   ├── TerminalLog.tsx           # Real-time protocol execution stream
│   └── UrlInput.tsx              # URL input controller & scan dispatch
├── App.tsx                       # Central orchestration, proxy failover & state
├── geminiService.ts              # Gemini 2.5 Flash prompt schemas & AI subroutines
├── index.html                    # Cyberpunk aesthetic, scanline overlays & imports
├── index.tsx                     # React client-side hydration entry
├── metadata.json                 # Project capabilities & environment manifest
├── package.json                  # Dependencies, build scripts & metadata
├── server.ts                     # Express server & high-performance proxy gateway
├── tsconfig.json                 # TypeScript compiler configuration
├── types.ts                      # Strict TypeScript interfaces & schemas
├── utils.ts                      # URL normalization & link resolution utilities
└── vite.config.ts                # Vite build and plugin configurations
```

---

## 8. Security & Ethical Operations Notice

> [!CAUTION]
> **Ghostwire Mk.III** is engineered for defensive security assessments, competitive intelligence gathering, accessibility compliance verification, and authorized OSINT investigations on public-facing assets.

- **Non-Destructive Execution**: Ghostwire Mk.III operates purely in a read-only passive reconnaissance capacity. It does not perform active vulnerability exploitation, denial-of-service, or authentication bypass.
- **Authorization**: Ensure you have explicit authorization or legitimate interest before scanning proprietary web properties.

---

<div align="center">
  <sub>Ghostwire Mk.III © 2026 // Autonomous Web Intelligence Protocol</sub>
</div>
