# ⚡ Ghostwire Mk.III — Advanced AI Web Reconnaissance Platform

**Ghostwire Mk.III** is a high-performance, generative AI-powered web reconnaissance and digital intelligence gathering platform. Built with React, TypeScript, Tailwind CSS, and Google's Gemini 2.5 Flash model, Ghostwire transforms raw web data and fully rendered client-side DOMs into structured, actionable intelligence reports.

---

## 🌟 Key Capabilities & Modules

### 1. 🛡️ Multi-Engine Proxy Pipeline
- **Dynamic Render Fetching**: Resilient multi-tier proxy architecture featuring RenderTron (JS-enabled headless DOM rendering), AllOrigins, and CodeTabs to bypass CORS limitations and capture client-side single-page applications (React, Vue, Angular).
- **Real-Time Terminal Protocol Logs**: Live streaming status logs tracking connection phases, handshake protocols, DOM extraction, and AI processing.

### 2. 🔍 Advanced Reconnaissance & Infrastructure Fingerprinting
- **Server & Hosting Intel**: Host platform, server IP address, geographical geolocation, and platform classification.
- **WAF & Security Layer**: Web Application Firewall detection and threat intelligence notes.
- **CMS & Frameworks**: Identification of CMS themes, active plugins, and granular software libraries with version detection.
- **CVE & Vulnerability Matrix**: Heuristic vulnerability mapping classified by severity (*Critical*, *High*, *Medium*, *Low*, *Informational*).

### 3. 👥 OSINT & Contact Harvesting
- **Digital Footprint Extraction**: Identification of public emails, telephone numbers, and physical mailing addresses.
- **Key Personnel**: Discovered leadership profiles, titles, and team members.
- **Social Profiles**: Aggregation of linked Twitter/X, LinkedIn, GitHub, and Facebook channels.

### 4. 🧠 Content & Linguistic Intelligence
- **Interactive Sentiment Gauge**: Visual radial meter scoring page tone from `-1.0` (negative) to `+1.0` (positive).
- **Readability & Language**: Automated assessment of linguistic grade-level complexity and detected dialect/language.
- **Key Entity & Topic Extraction**: Extraction of central entities and thematic tags.

### 5. ♿ Accessibility (A11y) Audit
- **Comprehensive A11y Scoring**: Overall accessibility compliance score (0–100).
- **Categorized Issue Tracking**: Severity classification (*Critical*, *Serious*, *Moderate*, *Minor*) with target element selectors and remediation notes.

### 6. 📈 SEO & Performance Analysis
- **Metadata Inspection**: Title tags, H1 heading hierarchies, meta descriptions, and keyword tags.
- **Social Graph Previews**: OpenGraph (OG) and Twitter Card card metadata extraction.
- **Performance Hints**: Concrete optimization tips based on DOM structure and content length.

### 7. 🔗 Link Categorization & Distribution
- **Visual Distribution Bar**: Split breakdown of internal, external, and social outbound links.
- **Collapsible Manifests**: Quick inspection and navigation across all extracted target endpoints.

### 8. 👁️ AI Vision Subroutine (Image Analysis)
- **Deep Image Inspection**: One-click secondary AI pass generating contextual, natural-language descriptions for all discovered media assets.

### 9. 🕷️ Deep Site Crawler
- **Recursive Internal Crawl**: Compiles internal link manifests and automatically crawls linked pages, summarizing each page's primary intelligence.

### 10. 💬 Intelligence Debriefing (AI Chat)
- **Grounded Interactive Analyst**: Chat interface grounded strictly in the collected reconnaissance data.
- **Suggested Tactical Queries**: Dynamic query chips for summarizing security risks, sentiment, and core findings.

### 11. 💾 Export & Data Portability
- **JSON Intelligence Dossier**: Full export of structured intelligence data for external tooling or offline archiving.
- **Integrated Clipboard Actions**: Rapid copying for IP addresses, domain metadata, emails, and phone numbers.

---

## 🛠️ Tech Stack

- **Frontend**: React 18, TypeScript, Tailwind CSS
- **AI Engine**: Google GenAI TypeScript SDK (`@google/genai`) powered by `gemini-2.5-flash`
- **Build System**: Vite 6, Node.js / ES2022
- **Aesthetic**: Cyberpunk high-contrast terminal UI with custom scanline overlays, neon status indicators, and monospace typography.

---

## 🚀 Getting Started

### Prerequisites
- Node.js (v18+)
- A Google Gemini API Key

### Installation

1. **Clone repository and install dependencies**:
   ```bash
   npm install
   ```

2. **Configure Environment Variables**:
   Create a `.env` or `.env.local` file in the project root:
   ```env
   GEMINI_API_KEY=your_gemini_api_key_here
   ```

3. **Start Development Server**:
   ```bash
   npm run dev
   ```
   The application will be available at `http://localhost:3000`.

4. **Production Build**:
   ```bash
   npm run build
   npm run start
   ```

---

## 📁 Project Directory Structure

```
├── components/
│   ├── AccessibilityCard.tsx     # A11y scoring and issue severity cards
│   ├── Card.tsx                  # Reusable terminal-themed container
│   ├── ChatInterface.tsx         # Intelligence Debriefing AI chat assistant
│   ├── ContentLanguageCard.tsx   # Sentiment gauge and linguistic metrics
│   ├── CopyToClipboard.tsx       # Quick clipboard copy utility
│   ├── Disclaimer.tsx            # Ethical usage guidelines & disclaimer
│   ├── LoadingSpinner.tsx        # Terminal loading animation
│   ├── ResultsDisplay.tsx        # Comprehensive reconnaissance dashboard
│   ├── TerminalLog.tsx           # Real-time protocol event stream
│   └── UrlInput.tsx              # URL input controller and scanner trigger
├── App.tsx                       # Main application state and orchestration
├── geminiService.ts              # Gemini 2.5 Flash prompts and SDK client
├── index.html                    # Cyberpunk styles, importmaps & scanlines
├── index.tsx                     # React application entry point
├── metadata.json                 # Project configuration and capabilities
├── types.ts                      # TypeScript data models and interfaces
├── utils.ts                      # URL normalization and helper utilities
└── vite.config.ts                # Vite build and proxy config
```

---

## 📝 Recent Updates & Changelog

### Version 3.1.0 — System Hardening & Maintenance
- **Fixed JSX Parsing in Chat Module**: Resolved JSX token formatting for tactical prompt prefixes (`&gt;`), restoring compilation stability for the Debriefing interface.
- **Model Upgrades**: Switched to `gemini-2.5-flash` for faster inference speeds, improved JSON schema adherence, and enhanced DOM parsing.
- **Resilient Fallbacks**: Multi-proxy failover routing with automatic protocol normalization (`http://` / `https://`).
- **Comprehensive Documentation**: Added complete README covering all active subroutines, modules, and API integrations.

---

## ⚖️ Legal & Ethical Usage Notice
Ghostwire Mk.III is built for authorized security assessments, OSINT research, and competitive intelligence gathering on public-facing web assets. Always ensure you have appropriate authorization before analyzing target systems.
