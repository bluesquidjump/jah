/**
 * JAH Background Script
 * Handles context menu, message passing, and API coordination
 */

// Known fingerprints database (loaded on startup)
let knownFingerprints = {};

// Local JA4DB status
let localDbReady = false;
let localDbSyncing = false;

// Cache for quick lookups (page scanning)
const quickLookupCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const FILE_HASH_CACHE_TTL = 60 * 60 * 1000; // 1 hour (file hashes are immutable)

// File hash enrichment cache
const fileHashCache = new Map();

// VT rate limiter (separate from JA4 - 4 requests/min for free tier)
const vtRateLimiter = {
  requests: [],
  maxRequests: 4,
  windowMs: 60000,

  canMakeRequest() {
    const now = Date.now();
    this.requests = this.requests.filter(t => now - t < this.windowMs);
    return this.requests.length < this.maxRequests;
  },

  recordRequest() {
    this.requests.push(Date.now());
  }
};

// Rate limiting for page scanning
// Increased from 20 to 100 to handle pages with many fingerprints
const rateLimiter = {
  requests: [],
  maxRequests: 100,
  windowMs: 60000,

  canMakeRequest() {
    const now = Date.now();
    this.requests = this.requests.filter(t => now - t < this.windowMs);
    return this.requests.length < this.maxRequests;
  },

  recordRequest() {
    this.requests.push(Date.now());
  }
};

// Load known fingerprints database
async function loadKnownFingerprints() {
  try {
    const response = await fetch(browser.runtime.getURL('data/known-fingerprints.json'));
    knownFingerprints = await response.json();
    console.log('JAH: Loaded known fingerprints database');
  } catch (error) {
    console.error('JAH: Failed to load known fingerprints:', error);
    knownFingerprints = { fingerprints: {} };
  }
}

// Initialize local JA4DB
async function initLocalJA4DB() {
  try {
    await JA4DBLocal.init();
    localDbReady = true;
    console.log('JAH: Local JA4DB initialized');

    // Check if initial sync is needed
    const needsSync = await JA4DBLocal.needsInitialSync();
    if (needsSync) {
      console.log('JAH: Initial sync required, starting download...');
      syncLocalJA4DB();
    } else {
      const stats = await JA4DBLocal.getStats();
      console.log(`JAH: Local JA4DB ready with ${stats.recordCount} records (last sync: ${stats.lastSync})`);
    }
  } catch (error) {
    console.error('JAH: Failed to initialize local JA4DB:', error);
    localDbReady = false;
  }
}

// Sync local JA4DB
async function syncLocalJA4DB(progressCallback = null) {
  if (localDbSyncing) {
    console.log('JAH: Sync already in progress');
    return { success: false, error: 'Sync already in progress' };
  }

  localDbSyncing = true;
  try {
    const result = await JA4DBLocal.syncDatabase(progressCallback);
    return result;
  } finally {
    localDbSyncing = false;
  }
}

// Set up daily sync alarm
function setupSyncAlarm() {
  browser.alarms.create('ja4db-sync', {
    periodInMinutes: 24 * 60 // Daily sync
  });
}

// Handle alarms
browser.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'ja4db-sync') {
    console.log('JAH: Running scheduled JA4DB sync');
    syncLocalJA4DB();
  }
});

// Initialize on startup
loadKnownFingerprints();
initLocalJA4DB();
setupSyncAlarm();

// Clean up old cache entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of quickLookupCache.entries()) {
    if (now - value.timestamp > CACHE_TTL) {
      quickLookupCache.delete(key);
    }
  }
  for (const [key, value] of fileHashCache.entries()) {
    if (now - value.timestamp > FILE_HASH_CACHE_TTL) {
      fileHashCache.delete(key);
    }
  }
}, 60000);

// Create context menu item (auto-detects JA4 fingerprints vs file hashes)
browser.contextMenus.create({
  id: 'jah-enrich',
  title: 'JAH Hash Enrichment',
  contexts: ['selection']
});

// Handle context menu clicks
browser.contextMenus.onClicked.addListener((info, tab) => {
  const selectedText = info.selectionText?.trim();
  if (!selectedText) return;

  if (info.menuItemId === 'jah-enrich') {
    const isValid = JA4Parser.isValid(selectedText);

    // Open sidebar FIRST (must be synchronous from user gesture)
    browser.sidebarAction.open();

    (async () => {
      try {
        if (isValid) {
          const parsed = JA4Parser.parse(selectedText);
          const isHash = parsed && JA4Parser.isFileHash(parsed.type);

          await browser.storage.local.set({
            pendingEnrichment: {
              hash: selectedText,
              isFileHash: isHash,
              sourceUrl: tab.url,
              sourceTitle: tab.title,
              timestamp: Date.now()
            }
          });
        } else {
          await browser.storage.local.set({
            pendingEnrichment: {
              error: 'Selected text does not appear to be a valid JA4 fingerprint or file hash (MD5, SHA1, SHA256).',
              text: selectedText,
              timestamp: Date.now()
            }
          });
        }
      } catch (e) {
        console.error('JAH: Failed to store pending enrichment:', e);
      }

      if (isValid) {
        const parsed = JA4Parser.parse(selectedText);
        const isHash = parsed && JA4Parser.isFileHash(parsed.type);
        const msgType = isHash ? 'enrich-file-hash' : 'enrich-hash';

        setTimeout(() => {
          try {
            browser.runtime.sendMessage({
              type: msgType,
              hash: selectedText,
              sourceUrl: tab.url,
              sourceTitle: tab.title
            });
          } catch (e) {
            // Sidebar will pick up from storage
          }
        }, 100);
      }
    })();
  }

});

// Handle messages from content script and sidebar
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'enrich-hash') {
    handleEnrichment(message.hash)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true; // Indicates async response
  }

  if (message.type === 'check-hash') {
    const isValid = JA4Parser.isValid(message.hash);
    const parsed = isValid ? JA4Parser.parse(message.hash) : null;
    sendResponse({ isValid, parsed });
    return false;
  }

  if (message.type === 'get-known-match') {
    const match = findKnownFingerprint(message.hash);
    sendResponse({ match });
    return false;
  }

  if (message.type === 'get-history') {
    getHistory().then(history => sendResponse({ history }));
    return true;
  }

  if (message.type === 'clear-history') {
    clearHistory().then(() => sendResponse({ success: true }));
    return true;
  }

  if (message.type === 'lookup-ja4db') {
    (async () => {
      try {
        // Prefer local database for instant lookup
        if (localDbReady) {
          const result = await JA4DBLocal.lookup(message.hash, message.fingerType);
          sendResponse(result);
        } else {
          // Fallback to remote API
          const result = await JA4DBClient.lookup(message.hash, message.fingerType);
          sendResponse(result);
        }
      } catch (error) {
        sendResponse({ found: false, error: error.message });
      }
    })();
    return true;
  }

  if (message.type === 'get-mcp-status') {
    MCPClient.getStatus()
      .then(status => sendResponse(status))
      .catch(error => sendResponse({ error: error.message }));
    return true;
  }

  if (message.type === 'configure-mcp') {
    MCPClient.configureIntegration(message.integration, message.settings)
      .then(() => sendResponse({ success: true }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }

  // Quick lookup for file hashes during page scanning (no VT calls)
  if (message.type === 'quick-lookup-hash') {
    handleQuickLookupHash(message.hash, message.fingerprintType)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ error: error.message }));
    return true;
  }

  // Full file hash enrichment (user-initiated)
  if (message.type === 'enrich-file-hash') {
    handleFileHashEnrichment(message.hash)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }

  // Quick lookup for page scanning (JA4DB only, no Claude)
  if (message.type === 'quick-lookup') {
    handleQuickLookup(message.hash, message.fingerprintType)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ error: error.message }));
    return true;
  }

  // Open sidebar and trigger enrichment (from icon click)
  if (message.type === 'open-sidebar-enrich') {
    // Auto-detect hash type
    const parsed = JA4Parser.parse(message.hash);
    const isFileHash = parsed && JA4Parser.isFileHash(parsed.type);
    const enrichType = isFileHash ? 'enrich-file-hash' : 'enrich-hash';

    // Open sidebar first
    browser.sidebarAction.open();

    // Store pending enrichment with type info
    browser.storage.local.set({
      pendingEnrichment: {
        hash: message.hash,
        isFileHash: isFileHash,
        timestamp: Date.now()
      }
    }).then(() => {
      // Send message to sidebar after brief delay
      setTimeout(() => {
        try {
          browser.runtime.sendMessage({
            type: enrichType,
            hash: message.hash
          });
        } catch (e) {
          // Sidebar will pick up from storage
        }
      }, 150);
    });

    sendResponse({ success: true });
    return false;
  }

  // Get settings for content script
  if (message.type === 'get-settings') {
    browser.storage.local.get(['claudeApiKey', 'claudeModel', 'scanEnabled', 'debugMode'])
      .then(result => sendResponse({
        hasApiKey: !!result.claudeApiKey,
        model: result.claudeModel || 'claude-sonnet-4-20250514',
        scanEnabled: result.scanEnabled !== false, // Default to true
        debugMode: result.debugMode === true // Default to false
      }))
      .catch(error => sendResponse({ error: error.message }));
    return true;
  }

  // Toggle debug mode
  if (message.type === 'set-debug-mode') {
    browser.storage.local.set({ debugMode: message.enabled })
      .then(() => sendResponse({ success: true, debugMode: message.enabled }))
      .catch(error => sendResponse({ error: error.message }));
    return true;
  }

  // Get local JA4DB status
  if (message.type === 'get-local-db-status') {
    (async () => {
      try {
        const stats = await JA4DBLocal.getStats();
        sendResponse({
          ready: localDbReady,
          syncing: localDbSyncing,
          ...stats
        });
      } catch (error) {
        sendResponse({
          ready: localDbReady,
          syncing: localDbSyncing,
          error: error.message
        });
      }
    })();
    return true;
  }

  // Force sync local JA4DB
  if (message.type === 'sync-local-db') {
    (async () => {
      const result = await syncLocalJA4DB((progress) => {
        // Send progress updates to popup if it's open
        try {
          browser.runtime.sendMessage({
            type: 'sync-progress',
            ...progress
          });
        } catch (e) {
          // Popup may be closed
        }
      });
      sendResponse(result);
    })();
    return true;
  }
});

/**
 * Handle quick lookup for page scanning (local JA4DB, no Claude)
 * Uses local IndexedDB for instant lookups - no rate limiting needed
 */
async function handleQuickLookup(hash, type) {
  const cacheKey = `${type}:${hash}`;

  // Check cache first
  const cached = quickLookupCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.result;
  }

  try {
    // Parse the fingerprint
    const parsed = JA4Parser.parse(hash);

    // Check local known fingerprints
    const knownMatch = findKnownFingerprint(hash);

    // Use local JA4DB for instant lookup (no rate limiting needed)
    let ja4dbResult;
    if (localDbReady) {
      ja4dbResult = await JA4DBLocal.lookup(hash, type);
    } else {
      // Fallback to remote if local not ready
      if (!rateLimiter.canMakeRequest()) {
        return {
          hash,
          type,
          error: 'Rate limit exceeded',
          rateLimited: true
        };
      }
      rateLimiter.recordRequest();
      ja4dbResult = await JA4DBClient.lookup(hash, type);
    }

    const result = {
      hash,
      type,
      parsed,
      knownMatch,
      ja4db: ja4dbResult,
      timestamp: new Date().toISOString()
    };

    // Cache the result
    quickLookupCache.set(cacheKey, {
      result,
      timestamp: Date.now()
    });

    return result;

  } catch (error) {
    console.error('JAH quick lookup error:', error);
    return {
      hash,
      type,
      error: error.message
    };
  }
}

/**
 * Handle fingerprint enrichment request
 */
async function handleEnrichment(hash) {
  // Parse the hash
  const parsed = JA4Parser.parse(hash);
  if (!parsed) {
    throw new Error('Failed to parse JA4 fingerprint');
  }

  // Check for known match in local database
  const knownMatch = findKnownFingerprint(hash);

  // Query JA4 Database (prefer local, fallback to remote)
  let ja4dbResult = null;
  try {
    if (localDbReady) {
      console.log('JAH: Querying local JA4 Database for', hash);
      ja4dbResult = await JA4DBLocal.lookup(hash, parsed.type);
    } else {
      console.log('JAH: Querying remote JA4 Database for', hash);
      ja4dbResult = await JA4DBClient.lookup(hash, parsed.type);
    }
    console.log('JAH: JA4DB result:', ja4dbResult.found ? 'found' : 'not found', `(${ja4dbResult.source || 'remote'})`);
  } catch (error) {
    console.warn('JAH: JA4DB lookup failed:', error.message);
  }

  // Fetch additional context from MCP integrations
  let mcpContext = null;
  try {
    const mcpAvailable = await MCPClient.isAvailable();
    if (mcpAvailable) {
      console.log('JAH: Fetching MCP context');
      mcpContext = await MCPClient.fetchContext(hash, parsed.type);
      console.log('JAH: MCP sources:', mcpContext.sources);
    }
  } catch (error) {
    console.warn('JAH: MCP context fetch failed:', error.message);
  }

  // Get enrichment from Claude API with all context
  const result = await ClaudeAPI.enrichHash(hash, parsed, knownMatch, ja4dbResult);

  // Save to history
  await saveToHistory({
    hash,
    type: parsed.type,
    knownMatch: knownMatch?.name || null,
    ja4dbFound: ja4dbResult?.found || false,
    summary: result.summary || null,
    assessment: result.assessment || null,
    timestamp: result.timestamp,
    analysis: result.analysis
  });

  return {
    success: true,
    hash,
    parsed,
    knownMatch,
    ja4dbResult,
    mcpContext,
    summary: result.summary,
    assessment: result.assessment,
    analysis: result.analysis,
    model: result.model,
    usage: result.usage,
    timestamp: result.timestamp
  };
}

/**
 * Handle quick lookup for file hashes during page scanning
 * Only checks local known-fingerprints.json, no external API calls
 */
async function handleQuickLookupHash(hash, type) {
  const cacheKey = `hash:${hash.toLowerCase()}`;

  // Check cache first
  const cached = quickLookupCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.result;
  }

  const normalizedHash = hash.toLowerCase().trim();
  const knownMatch = findKnownFingerprint(normalizedHash);

  const result = {
    hash: normalizedHash,
    type,
    isFileHash: true,
    knownMatch,
    timestamp: new Date().toISOString()
  };

  // Determine category from known match
  if (knownMatch) {
    result.assessment = {
      category: knownMatch.category || 'unknown',
      threatLevel: knownMatch.category === 'malware' ? 'critical' : 'none',
      confidence: knownMatch.confidence || 'medium'
    };
  }

  quickLookupCache.set(cacheKey, { result, timestamp: Date.now() });
  return result;
}

/**
 * Handle full file hash enrichment (user-initiated)
 * Queries threat intel APIs and Claude
 */
async function handleFileHashEnrichment(hash) {
  const normalizedHash = hash.toLowerCase().trim();
  const hashType = JA4Parser.detectFileHashType(normalizedHash);

  if (!hashType) {
    throw new Error('Invalid file hash format');
  }

  // Check cache (1-hour TTL for file hashes)
  const cached = fileHashCache.get(normalizedHash);
  if (cached && Date.now() - cached.timestamp < FILE_HASH_CACHE_TTL) {
    return cached.result;
  }

  // Check known fingerprints
  const knownMatch = findKnownFingerprint(normalizedHash);

  // Get threat intel config
  const mcpConfig = await MCPClient.getConfig();
  const threatIntelConfig = {
    virusTotalApiKey: mcpConfig.threatIntel?.virusTotalApiKey || null,
    otxApiKey: mcpConfig.threatIntel?.otxApiKey || null
  };

  // Query all threat intel sources in parallel
  console.log('JAH: Querying threat intel for file hash:', normalizedHash);
  const threatContext = await ThreatIntelClient.queryAll(normalizedHash, threatIntelConfig);
  console.log('JAH: Threat intel results:', {
    vt: threatContext.virusTotal?.found,
    mb: threatContext.malwareBazaar?.found,
    otx: threatContext.alienVaultOTX?.found,
    errors: threatContext.errors.length
  });

  // Call Claude for analysis
  const claudeResult = await ClaudeAPI.enrichFileHash(
    normalizedHash,
    hashType,
    threatContext,
    knownMatch
  );

  const result = {
    success: true,
    hash: normalizedHash,
    isFileHash: true,
    parsed: {
      type: hashType,
      raw: normalizedHash,
      isFileHash: true,
      components: {
        hashAlgorithm: hashType,
        hashValue: normalizedHash,
        length: normalizedHash.length
      }
    },
    knownMatch,
    threatIntel: threatContext,
    summary: claudeResult.summary,
    assessment: claudeResult.assessment,
    analysis: claudeResult.analysis,
    model: claudeResult.model,
    usage: claudeResult.usage,
    timestamp: claudeResult.timestamp
  };

  // Cache result
  fileHashCache.set(normalizedHash, { result, timestamp: Date.now() });

  // Also cache all hash variants if VT returned them
  const vt = threatContext.virusTotal;
  if (vt && vt.found) {
    const aliases = [vt.sha256, vt.sha1, vt.md5].filter(h => h && h !== normalizedHash);
    for (const alias of aliases) {
      fileHashCache.set(alias.toLowerCase(), { result, timestamp: Date.now() });
    }
  }

  // Save to history
  await saveToHistory({
    hash: normalizedHash,
    type: hashType,
    isFileHash: true,
    knownMatch: knownMatch?.name || null,
    summary: result.summary || null,
    assessment: result.assessment || null,
    timestamp: result.timestamp,
    analysis: result.analysis
  });

  return result;
}

/**
 * Find a known fingerprint match in local database
 */
function findKnownFingerprint(hash) {
  const normalized = hash.toLowerCase().trim();

  // Direct lookup
  if (knownFingerprints.fingerprints?.[normalized]) {
    return knownFingerprints.fingerprints[normalized];
  }

  // Check by prefix (for partial matches)
  const prefix = normalized.split('_')[0];
  for (const [key, value] of Object.entries(knownFingerprints.fingerprints || {})) {
    if (key.startsWith(prefix) && value.partialMatch) {
      return { ...value, partialMatch: true };
    }
  }

  return null;
}

/**
 * Get enrichment history
 */
async function getHistory() {
  const result = await browser.storage.local.get('enrichmentHistory');
  return result.enrichmentHistory || [];
}

/**
 * Save enrichment to history
 */
async function saveToHistory(entry) {
  const history = await getHistory();

  // Add new entry at the beginning
  history.unshift(entry);

  // Keep only last 50 entries
  const trimmed = history.slice(0, 50);

  await browser.storage.local.set({ enrichmentHistory: trimmed });
}

/**
 * Clear enrichment history
 */
async function clearHistory() {
  await browser.storage.local.set({ enrichmentHistory: [] });
}

console.log('JAH Background script loaded');
