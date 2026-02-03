# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

JAH (JA4 Hash Enrichment) is a Firefox WebExtension (Manifest V2) that detects JA4+ fingerprints on web pages and enriches them with threat intelligence using Claude AI and the JA4 Database (ja4db.com).

## Development Commands

```bash
# Load extension for development
# 1. Open Firefox and go to about:debugging
# 2. Click "This Firefox" → "Load Temporary Add-on..."
# 3. Select manifest.json

# Package for distribution
web-ext build

# Sign with Mozilla (uses environment variables)
web-ext sign --api-key="$MOZILLA_API_KEY" --api-secret="$MOZILLA_API_SECRET" --channel=unlisted
```

**Note:** Mozilla signing credentials are configured as environment variables `MOZILLA_API_KEY` and `MOZILLA_API_SECRET`. Always use these variables - never hardcode credentials.

No build step required - pure JavaScript. Test manually using `test/test-page.html` which contains sample fingerprints.

## Architecture

Four execution contexts communicate via message passing:

```
Content Script (content.js)     → Scans pages, injects fox icons
        ↓ messages
Background Script (background.js) → Routes messages, caches results, manages history
        ↓ messages
Sidebar (sidebar.js)            → Displays full analysis UI
Popup (popup.js)                → Toolbar button quick access
Options (options.js)            → Settings/API key configuration
```

**Shared libraries** in `lib/`:
- `ja4-parser.js` - Fingerprint detection and parsing (regex patterns for JA4, JA4S, JA4H, JA4X, JA4SSH, JA4T, JA4TS)
- `ja4db-client.js` - JA4 Database API client with type-aware processing
- `claude-api.js` - Claude AI integration with structured assessment output
- `mcp-client.js` - Optional integrations (Brave Search, VirusTotal, Shodan)

**Data flow for enrichment:**
1. Content script detects fingerprint → sends to background
2. Background validates, checks cache (5min TTL)
3. Queries local JA4DB (IndexedDB, ~258K records), falls back to remote API if local not ready
4. For full analysis, queries Claude API with parsed components + database results
5. Result cached and added to history (last 50 stored)
6. Sidebar displays with category color coding based on LLM assessment

## Key Implementation Details

### Structured Assessment System (v1.1.5+)

Claude returns a structured assessment line at the end of each analysis:
```
ASSESSMENT: [category] | [threat_level] | [confidence]
```

- **Categories**: browser, vpn, malware, tool, library, bot, suspicious, benign
- **Threat levels**: critical, high, medium, low, none
- **Confidence**: high, medium, low

This is parsed by `ClaudeAPI.extractAssessment()` and drives the fox icon color coding.

### Type-Aware JA4DB Processing

JA4DB records often contain multiple fingerprint types (ja4, ja4s, ja4h, etc.) in a single record. When querying by one type (e.g., JA4S), an application label in that record may actually be associated with a different fingerprint type (e.g., the JA4).

`JA4DBClient.processResults()` now tracks:
- **directApplications**: Applications identified by the queried fingerprint type
- **relatedApplications**: Applications identified by OTHER fingerprint types in the same record

This prevents misattribution (e.g., a JA4S query being flagged as Sliver malware when Sliver is actually identified by the JA4 fingerprint in that record).

### Category Determination Priority

In `content.js determineCategory()`:
1. Claude's structured assessment (highest priority)
2. Local known fingerprints database match
3. JA4DB direct applications (only those matching queried type)
4. Falls back to unknown if no data

**Fingerprint categories** (defined in content.js `validateCategory()`):
- malware (red), suspicious (orange), bot (orange), browser (green), benign (green), tool (navy), vpn (blue), library (light blue)

### Storage Keys (browser.storage.local)
- `claudeApiKey`, `claudeModel`, `mcpConfig`, `enrichmentHistory`, `scanEnabled`, `pendingEnrichment`

**Known fingerprints database**: `data/known-fingerprints.json` - offline lookup before API queries

## Extension Points

**Add new fingerprint type**: Update regex in `JA4Parser.patterns` and add `parseJA4*()` method in `lib/ja4-parser.js`

**Add new category**: Update `validateCategory()` in content.js, add CSS in content.css and sidebar.css, add to `categories` in known-fingerprints.json

**Add API integration**: Extend `MCPClient` in lib/mcp-client.js, add UI in options.js

## Release Process

When prompted to prepare a new release, perform ALL of the following steps automatically:

1. Bump version in `manifest.json` and `sidebar/sidebar.html` footer
2. Commit all changes with descriptive message
3. Create git tag: `git tag -a vX.X.X -m "Release notes"`
4. Push commits and tag: `git push origin main && git push origin vX.X.X`
5. Sign extension with Mozilla:
   ```bash
   web-ext sign --api-key="$MOZILLA_API_KEY" --api-secret="$MOZILLA_API_SECRET" --channel=unlisted
   ```
6. Create GitHub Release and upload the signed XPI:
   ```bash
   gh release create vX.X.X --title "..." --notes "..." <signed-xpi-file>
   ```

**IMPORTANT:**
- `MOZILLA_API_KEY` and `MOZILLA_API_SECRET` are configured in `~/.bashrc` (above the interactive guard). These are available as environment variables in all shells — use them directly, never hardcode credentials
- Always sign the XPI and upload it to the GitHub Release as part of the release process
- Always create and push a new GitHub Release when changes are complete - do not wait to be asked
- Never commit credentials to the repository

## Recent Changes

### v1.2.1
- Improved file hash confidence scoring for CTI pages (CrowdStrike, Mandiant, Unit42, etc.)
- Added page prescan for hash candidates before DOM walk
- Semantic element scores accumulate (e.g., `<code>` inside `<td>` = 25pts)
- Table header CTI keyword checking with `<thead>` and first-`<tr>` fallback
- Unified context menu into single "JAH Hash Enrichment" with auto-detection
- Sidebar only shows loading steps relevant to the hash type being analyzed
- Added generic `.hidden` CSS rule, updated sidebar subtitle

### v1.2.0
- File hash detection (MD5, SHA1, SHA256) with confidence scoring to reduce false positives
- Threat intel enrichment via VirusTotal, MalwareBazaar, and AlienVault OTX
- Bug icon for file hash indicators (distinct from JA4 fox icons)
- SVG donut chart for VirusTotal detection ratios in sidebar
- Client-side LLM output validation guardrails
- `lib/threat-intel-client.js` — new API client for threat intel services
- OTX API key configuration in options page

### v1.1.8
- Added local JA4DB using IndexedDB for instant lookups (~258K records)
- Full database downloaded on first extension load
- Eliminated rate limiting for high-volume pages (Zeek results, etc.)
- Popup shows database status, last sync time, and manual sync button
- Daily auto-sync with diff-based updates (only changes written)
- Added alarms permission for scheduled sync

### v1.1.7
- Fixed JA4S fingerprints incorrectly showing client application (e.g., Sliver) when it's the JA4 that identifies the malware
- Tooltip now shows "Server response (client was X)" for JA4S fingerprints with related applications
- Color coding now applied when JA4DB record is verified OR LLM assessment has high confidence
- Added purple "verified" styling for verified JA4DB records
- Added pulse animation for high-confidence assessments

### v1.1.6
- Added debug mode with console access via `window.JAH_DEBUG`
- Fox icons now show for ALL detected fingerprints (not just JA4DB matches)
- Fixed JA4S regex to match variants with alphanumeric suffixes (e.g., `t1203h1_...`)
- Much more visible category colors with double drop-shadow and radial gradients
- Increased rate limit from 20 to 100 requests/60s
- Added styling for unverified, rate-limited, and error states

### v1.1.5
- Added structured ASSESSMENT output parsing from Claude responses
- JA4DB results now distinguish direct vs related applications by fingerprint type
- LLM assessment drives fox icon color coding (previously only used JA4DB/local DB)
- Added 'benign' category with green styling
- Assessment badge in sidebar shows category, threat level, confidence
