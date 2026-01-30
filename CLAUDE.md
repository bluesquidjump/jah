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

# Sign with Mozilla (requires API credentials)
web-ext sign --api-key=<key> --api-secret=<secret> --channel=unlisted
```

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
2. Background validates, checks cache (5min TTL), applies rate limiting (20/60s)
3. Queries JA4DB, then Claude API with parsed components + database results
4. Result cached and added to history (last 50 stored)
5. Sidebar displays with category color coding based on LLM assessment

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

## Recent Changes (v1.1.5)

- Added structured ASSESSMENT output parsing from Claude responses
- JA4DB results now distinguish direct vs related applications by fingerprint type
- LLM assessment drives fox icon color coding (previously only used JA4DB/local DB)
- Added 'benign' category with green styling
- Assessment badge in sidebar shows category, threat level, confidence
