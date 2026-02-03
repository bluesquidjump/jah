# JAH — JA4 Hash Enrichment

<p align="center">
  <img src="kitsune.png" alt="JAH Logo" width="150" height="150">
</p>

<p align="center">
  <strong>A Firefox extension for analyzing JA4+ fingerprints and file hashes</strong><br>
  <em>Powered by Claude AI, JA4 Database, VirusTotal, MalwareBazaar, and AlienVault OTX</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Firefox-Extension-FF7139?logo=firefox" alt="Firefox Extension">
  <img src="https://img.shields.io/badge/JA4+-Fingerprints-004b87" alt="JA4+ Fingerprints">
  <img src="https://img.shields.io/badge/File_Hashes-MD5%20SHA1%20SHA256-6b21a8" alt="File Hashes">
  <img src="https://img.shields.io/badge/Claude-AI-117aca" alt="Claude AI">
</p>

---

## What is JAH?

JAH (JA4 Hash Enrichment) is a Firefox extension that helps security analysts, threat hunters, and researchers quickly identify and analyze JA4+ fingerprints and file hashes found on web pages.

**For JA4+ fingerprints**, JAH:
1. **Flags them** with a fox icon showing the threat category
2. **Looks them up** in the JA4 Database (ja4db.com)
3. **Analyzes them** using Claude AI for detailed threat intelligence

**For file hashes** (MD5, SHA1, SHA256), JAH:
1. **Flags them** with a bug icon using confidence-based detection
2. **Queries threat intelligence** via VirusTotal, MalwareBazaar, and AlienVault OTX
3. **Analyzes them** using Claude AI with a safety-constrained malware analyst prompt
4. **Displays detection ratios** with an SVG donut chart for VirusTotal results

<p align="center">
  <img src="assets/workflow.svg" alt="JAH Workflow" width="700">
</p>

---

## What are JA4+ Fingerprints?

[JA4+](https://github.com/FoxIO-LLC/ja4) is a suite of network fingerprinting methods created by FoxIO that identify TLS clients, servers, HTTP clients, and more. These fingerprints are invaluable for:

- **Threat Detection** — Identifying malware C2 frameworks like Sliver, Cobalt Strike, and Metasploit
- **Attribution** — Tracking threat actors across infrastructure
- **Behavioral Analysis** — Understanding client/server relationships
- **Anomaly Detection** — Spotting unusual TLS implementations

### Supported Fingerprint Types

| Type | Description | Example |
|------|-------------|---------|
| **JA4** | TLS Client Fingerprint | `t13d1516h2_8daaf6152771_b0da82dd1658` |
| **JA4S** | TLS Server Fingerprint | `t130200_1301_234ea6891581` |
| **JA4H** | HTTP Client Fingerprint | `ge11cn20enus_60ca1bd65281_ac95b44401d9_8df6a44f726c` |
| **JA4SSH** | SSH Fingerprint | `c76s56p21_i76o21` |

### Supported File Hash Types

| Type | Length | Example |
|------|--------|---------|
| **SHA256** | 64 hex chars | `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` |
| **SHA1** | 40 hex chars | `3395856ce81f2b7382dee72602f798b642f14140` |
| **MD5** | 32 hex chars | `44d88612fea8a8f36de82e1278abb02f` |

---

## Features

### Automatic Page Scanning

JAH automatically scans web pages for JA4 fingerprints and file hashes. Detected items are marked with icons:

- **Fox icon** for JA4+ fingerprints
- **Bug icon** for file hashes (MD5, SHA1, SHA256)

Both icons glow with a color indicating the threat category.

<p align="center">
  <img src="assets/category-legend.svg" alt="Category Legend" width="600">
</p>

### Category Color Coding

The category color coding is very much a work-in-progress. What even kind of sense do these make.

| Category | Color | Description |
|----------|-------|-------------|
| **Malware** | Red | Known malware, C2 frameworks (Sliver, Cobalt Strike, etc.) |
| **Suspicious** | Orange | Potentially concerning fingerprints |
| **Bot** | Orange | Web crawlers and automated tools |
| **Browser** | Green | Legitimate web browsers (Chrome, Firefox, Safari) |
| **Benign** | Green | Safe, legitimate applications (AI-assessed) |
| **Tool** | Navy | CLI tools (curl, wget) |
| **VPN** | Blue | VPN clients |
| **Library** | Light Blue | Programming libraries (Python requests, Go net/http) |
| **Unknown** | Grey | Not yet enriched or no data available |

### File Hash Confidence Scoring

To reduce false positives, file hashes are scored (0-100) before detection. Positive signals include:

- Nearby CTI labels (`SHA256:`, `MD5:`, `IOC`, `malware`, `checksum`)
- CTI-related page context (VirusTotal, threat intel sites)
- Semantic HTML elements (`<code>`, `<pre>`, `<td>`)
- Multiple hashes on the same page (IOC list signal)
- SHA256 length bonus (64 chars are rarely false positives)

Negative signals that suppress detection:
- UUID patterns (8-4-4-4-12 format)
- CSS color context (`#ff6b35`, `background-color:`)
- Git context (`commit`, `merge`, `branch`)
- URL path segments

### VirusTotal Detection Donut Chart

For file hashes, the sidebar displays an SVG donut chart showing:
- Detection ratio (e.g., 45/72 engines)
- Color-coded by severity (red >50%, orange >20%, amber >0%, green 0%)
- Expandable vendor detection list
- Stats breakdown (malicious / suspicious / clean)

### Threat Intelligence Integration

File hash enrichment queries multiple sources in parallel:

| Source | API Key Required | Data Provided |
|--------|-----------------|---------------|
| **VirusTotal** | Yes | Detection ratios, vendor results, file metadata |
| **MalwareBazaar** (abuse.ch) | No | Malware family, tags, delivery method, first seen |
| **AlienVault OTX** | Yes | Pulse count, related reports, malware families |

### Quick Analysis Popup

Click any fox or bug icon to see a quick analysis popup:

<p align="center">
  <img src="assets/popup-panel.svg" alt="Popup Panel" width="320">
</p>

The popup shows:
- Fingerprint/hash type and value
- Threat category badge
- JA4DB matches (for fingerprints) or VT detection stats (for hashes)

### Full Sidebar Analysis

For detailed analysis, open the JAH sidebar (View → Sidebar → JAH):

<p align="center">
  <img src="assets/sidebar-preview.svg" alt="Sidebar Preview" width="300">
</p>

The sidebar provides:
- **Assessment Badge** — Category, threat level, and confidence from Claude AI
- **AI-Generated Summary** — Claude analyzes the fingerprint/hash and provides context
- **JA4 Database Results** — Applications, libraries, user agents (for JA4 fingerprints)
- **VirusTotal Detection Circle** — Visual detection ratio (for file hashes)
- **Threat Intel Results** — MalwareBazaar and OTX data (for file hashes)
- **Parsed Components** — Breakdown of protocol version, SNI, cipher suites, etc.
- **Detailed Analysis** — In-depth threat intelligence and recommendations
- **Lookup History** — Quick access to previous analyses

### Right-Click Enrichment

Select any JA4 fingerprint or file hash text, right-click, and choose "Enrich JA4 Hash" or "Enrich File Hash" to analyze it immediately.

---

## Installation

### Signed Extension (Recommended)

Download the latest signed `.xpi` from the [Releases](https://github.com/bluesquidjump/jah/releases) page, then:

1. Open Firefox
2. Go to `about:addons` (or menu → Add-ons and themes)
3. Click the **gear icon** at the top
4. Select **"Install Add-on From File..."**
5. Choose the downloaded `.xpi` file
6. Click **Add** when prompted

The extension will be permanently installed and persist across browser restarts.

### From Source (Development)

For development or testing the latest changes:

1. Clone this repository:
   ```bash
   git clone https://github.com/bluesquidjump/jah.git
   ```

2. Open Firefox and navigate to `about:debugging`

3. Click "This Firefox" in the sidebar

4. Click "Load Temporary Add-on..."

5. Navigate to the `jah` folder and select `manifest.json`

> **Note:** Temporary add-ons are removed when Firefox closes. For permanent installation, use the signed extension above or [sign your own build](https://extensionworkshop.com/documentation/develop/getting-started-with-web-ext/#signing-your-extension-for-self-distribution).

### Configuration

1. Click the gear icon in the JAH sidebar or go to the extension options

2. Enter your **Claude API Key** from [console.anthropic.com](https://console.anthropic.com/)

3. (Optional) Configure additional integrations:
   - **VirusTotal** — File hash lookups and detection ratios (API key required)
   - **AlienVault OTX** — Threat intelligence pulse data (free API key)
   - **MalwareBazaar** — Malware family identification (no API key needed)
   - **Brave Search API** — Web search for threat intelligence
   - **Shodan** — Infrastructure searches

---

## Usage

### Automatic Detection

Simply browse the web. When JAH detects a JA4 fingerprint or file hash:

1. A **fox icon** (JA4) or **bug icon** (hash) appears next to the detected item
2. The icon **glows** with a color indicating the category
3. **Hover** to see a quick tooltip
4. **Click** to open the analysis popup

### Manual Analysis

1. **Select** any JA4 fingerprint or file hash text on a page
2. **Right-click** and choose "Enrich JA4 Hash" or "Enrich File Hash"
3. The sidebar opens with full analysis

### Viewing History

1. Open the JAH sidebar (View → Sidebar → JAH)
2. Click "Recent Lookups" at the bottom
3. Click any previous lookup to view it again

---

## Example Fingerprints

Test JAH with these known fingerprints:

| Fingerprint | Application |
|-------------|-------------|
| `t13d1517h2_8daaf6152771_b0da82dd1658` | Chrome (Windows) |
| `t13d1516h2_8daaf6152771_02713d6af862` | Firefox |
| `t12d5909h1_e8f1e7e78f70_9aade0eb1cf0` | curl |

### Example File Hashes

| Hash | Description |
|------|-------------|
| `44d88612fea8a8f36de82e1278abb02f` | EICAR test file (MD5) |
| `3395856ce81f2b7382dee72602f798b642f14140` | EICAR test file (SHA1) |
| `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` | EICAR test file (SHA256) |

Test pages are included at `test/test-page.html` and `test/test-hash-detection.html`.

---

## Malware Detection

JAH automatically identifies fingerprints associated with known malware and offensive tools:

- **Sliver** — Red team C2 framework
- **Cobalt Strike** — Commercial adversary simulation
- **Metasploit/Meterpreter** — Penetration testing framework
- **Brute Ratel** — Red team C2 framework
- **Havoc** — Open-source C2 framework
- **Empire** — Post-exploitation framework
- **AsyncRAT/QuasarRAT** — Remote access trojans
- And many more...

When a malware fingerprint is detected, JAH displays it with a **red glow** and **MALWARE badge**.

For file hashes, JAH queries VirusTotal for multi-engine detection results and displays the detection ratio alongside the malware family name from MalwareBazaar.

---

## Privacy & Security

### Data Handling

- **API Keys** are stored locally in Firefox's extension storage (`browser.storage.local`)
- **No telemetry** — JAH does not collect or send analytics data
- **JA4DB queries** are made directly to ja4db.com
- **Claude API calls** are made directly to api.anthropic.com
- **File hash queries** send only the hash string to VirusTotal, MalwareBazaar, and OTX — never page URLs, titles, or user data
- **Results are cached locally** to minimize repeat API calls (5-min TTL for JA4, 1-hour TTL for file hashes)

### AI Safety & Prompt Injection Protections

JAH implements a 3-layer defense system for AI-generated content:

**Layer 1 — Input Validation:**
- All inputs are strictly validated before reaching Claude (regex-matched fingerprint/hash formats only)
- No user-provided free text reaches the LLM prompt
- External data (JA4DB results, threat intel responses) is incorporated as structured data

**Layer 2 — Prompt Engineering:**
- System prompts define a scoped analyst role with explicit forbidden content lists
- File hash analysis uses a dedicated `FILE_HASH_SYSTEM_PROMPT` that prohibits suggesting file download, execution, or detonation
- Output format is constrained to structured sections ending with a parseable `ASSESSMENT:` line

**Layer 3 — Output Validation:**
- `validateResponse()` runs on all Claude responses (both JA4 and file hash paths)
- Regex-based content safety checks reject responses containing:
  - Download commands targeting malware samples (`wget`/`curl` + malware keywords)
  - Execution instructions (`execute`/`run`/`detonate` + payload keywords)
  - Destructive system commands (`rm -rf`, `format c:`, reverse shells)
- `extractAssessment()` validates category, threat level, and confidence against hardcoded allowlists
- Failed validation returns a sanitized response with a safety warning

### Content Security Policy

The extension enforces a strict CSP (`script-src 'self'; object-src 'self'`) that prevents inline scripts and external script loading in extension pages.

### Extension Permissions

All permissions are scoped to the minimum required:

| Permission | Purpose |
|------------|---------|
| `storage` | Store API keys, settings, and history |
| `contextMenus` | Right-click enrichment options |
| `activeTab` | Read selected text for analysis |
| `alarms` | Schedule daily JA4DB sync |
| `https://api.anthropic.com/*` | Claude AI API calls |
| `https://ja4db.com/*` | JA4 Database lookups and download |
| `https://www.virustotal.com/*` | VirusTotal file hash lookups |
| `https://mb-api.abuse.ch/*` | MalwareBazaar malware lookups |
| `https://otx.alienvault.com/*` | AlienVault OTX threat intel |

---

## Technical Details

### Architecture

```
jah/
├── manifest.json              # Extension manifest (Manifest V2)
├── background/                # Background script
│   └── background.js          # API coordination, caching, message routing
├── content/                   # Content scripts
│   ├── content.js             # Page scanning, fox/bug icons, confidence scoring
│   └── content.css            # Styling and category color coding
├── sidebar/                   # Sidebar panel
│   ├── sidebar.html           # VT donut chart, threat intel sections
│   ├── sidebar.css
│   └── sidebar.js             # Result display, VT circle rendering
├── options/                   # Settings page
│   ├── options.html           # API key configuration
│   ├── options.css
│   └── options.js
├── lib/                       # Shared libraries
│   ├── ja4-parser.js          # JA4 fingerprint + file hash parsing
│   ├── ja4db-client.js        # JA4DB remote API client
│   ├── ja4db-local.js         # Local IndexedDB manager (~258K records)
│   ├── threat-intel-client.js # VirusTotal, MalwareBazaar, OTX clients
│   ├── claude-api.js          # Claude AI client + output validation
│   └── mcp-client.js          # Optional integrations (Brave, Shodan)
├── data/                      # Static data
│   └── known-fingerprints.json # Offline lookup database
├── icons/                     # Extension icons
│   ├── hash-bug.svg           # Bug icon for file hashes
│   └── ja4-fox-flag.png       # Fox icon for JA4 fingerprints
└── test/                      # Test pages
    ├── test-page.html         # Combined JA4 + hash test page
    └── test-hash-detection.html # Hash detection + false positive tests
```

---

## Changelog

### v1.2.0 (2026-02-03)
- **File Hash Detection** — Detects MD5, SHA1, and SHA256 hashes on web pages with confidence-based scoring
- **Bug Icon** — Distinct beetle icon for file hashes (separate from JA4 fox icon) with full category color coding
- **VirusTotal Integration** — Queries VT v3 API for multi-engine detection results with SVG donut chart display
- **MalwareBazaar Integration** — Queries abuse.ch for malware family, tags, and delivery method (no API key required)
- **AlienVault OTX Integration** — Queries OTX for threat intelligence pulse data
- **Confidence Scoring** — Reduces false positives by scoring hash context (CTI labels, page context, semantic elements, git/UUID/CSS rejection)
- **AI Safety Guardrails** — `validateResponse()` now applied to all Claude responses; file hash analysis uses a safety-constrained system prompt
- **Content Security Policy** — Added explicit CSP to manifest (`script-src 'self'; object-src 'self'`)
- **URL Encoding** — Fixed missing `encodeURIComponent` in VirusTotal and Shodan API URLs
- **Security Hardening** — Security audit and sensitive info scan performed; removed tracked backup files

### v1.1.8 (2026-01-30)
- **Local JA4DB** — Downloads full JA4 Database (~258K records) to IndexedDB for instant lookups
- **No Rate Limits** — Local database eliminates API rate limiting for high-volume pages (Zeek results, etc.)
- **Popup Sync UI** — Toolbar popup shows database status, last sync time, and manual sync button
- **Auto-Sync** — Daily automatic sync keeps local database up-to-date
- **Diff-Based Sync** — Uses content hashing to minimize database writes during sync

### v1.1.7 (2026-01-30)
- **Fixed JA4S Attribution** — JA4S (server) fingerprints no longer incorrectly labeled with client application names
- **Smarter Tooltips** — Shows "Server response (client was X)" for JA4S fingerprints
- **Verified Styling** — Purple glow for JA4DB verified records
- **High Confidence Indicator** — Pulse animation for high-confidence LLM assessments

### v1.1.6 (2026-01-30)
- **Debug Mode** — Console access via `window.JAH_DEBUG` for troubleshooting
- **Fox Icons for All Fingerprints** — Now shows icons for all detected fingerprints, not just JA4DB matches
- **Improved JA4S Detection** — Fixed regex to match fingerprint variants with alphanumeric suffixes
- **Enhanced Visibility** — Much brighter category colors with double glow effects
- **Higher Rate Limit** — Increased from 20 to 100 requests/minute for pages with many fingerprints

### v1.1.5 (2026-01-30)
- **LLM-Driven Categorization** — Claude's structured assessment now drives fox icon color coding
- **Assessment Badge** — Sidebar displays category, threat level, and confidence
- **Type-Aware JA4DB Processing** — Distinguishes direct vs related fingerprint associations to prevent misattribution
- **Benign Category** — New category for AI-assessed safe applications

### v1.1.4 (2026-01-29)
- Updated all icons to kitsune design
- Added browser toolbar button

### v1.1.3 (2026-01-29)
- Visual assets and styling improvements

### v1.1.2 (2026-01-29)
- CSS rebranding to generic JAH naming

### v1.1.1 (2026-01-29)
- Mozilla-signed extension for permanent installation
- Fixed fox icon click behavior (inline popup panel)
- Fixed malware category color coding
- Added comprehensive README with visual assets

---

## Credits

- **JA4+ Fingerprinting** by [FoxIO](https://github.com/FoxIO-LLC/ja4)
- **JA4 Database** at [ja4db.com](https://ja4db.com)
- **Claude AI** by [Anthropic](https://anthropic.com)
- **VirusTotal** by [Google/Chronicle](https://www.virustotal.com)
- **MalwareBazaar** by [abuse.ch](https://bazaar.abuse.ch)
- **AlienVault OTX** by [AT&T Cybersecurity](https://otx.alienvault.com)

---

## License

MIT License — See [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built for security analysts, by security analysts.</sub>
</p>
