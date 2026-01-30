/**
 * JAH Background Script
 * Handles context menu, message passing, and API coordination
 */

// Known fingerprints database (loaded on startup)
let knownFingerprints = {};

// Cache for quick lookups (page scanning)
const quickLookupCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Rate limiting for page scanning
const rateLimiter = {
  requests: [],
  maxRequests: 20,
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

// Initialize on startup
loadKnownFingerprints();

// Clean up old cache entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of quickLookupCache.entries()) {
    if (now - value.timestamp > CACHE_TTL) {
      quickLookupCache.delete(key);
    }
  }
}, 60000);

// Create context menu item
browser.contextMenus.create({
  id: 'jah-enrich',
  title: 'Enrich JA4 Hash',
  contexts: ['selection']
});

// Handle context menu clicks
browser.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId !== 'jah-enrich') return;

  const selectedText = info.selectionText?.trim();
  if (!selectedText) return;

  const isValid = JA4Parser.isValid(selectedText);

  // Open sidebar FIRST (must be synchronous from user gesture)
  browser.sidebarAction.open();

  // Then store pending enrichment and send message asynchronously
  (async () => {
    // Store the pending enrichment request
    try {
      if (isValid) {
        await browser.storage.local.set({
          pendingEnrichment: {
            hash: selectedText,
            sourceUrl: tab.url,
            sourceTitle: tab.title,
            timestamp: Date.now()
          }
        });
      } else {
        await browser.storage.local.set({
          pendingEnrichment: {
            error: 'Selected text does not appear to be a valid JA4 fingerprint.',
            text: selectedText,
            timestamp: Date.now()
          }
        });
      }
    } catch (e) {
      console.error('JAH: Failed to store pending enrichment:', e);
    }

    // Send message directly (in case sidebar is already open)
    if (isValid) {
      // Small delay to let sidebar initialize if it just opened
      setTimeout(() => {
        try {
          browser.runtime.sendMessage({
            type: 'enrich-hash',
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
    JA4DBClient.lookup(message.hash, message.fingerType)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ found: false, error: error.message }));
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

  // Quick lookup for page scanning (JA4DB only, no Claude)
  if (message.type === 'quick-lookup') {
    handleQuickLookup(message.hash, message.fingerprintType)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ error: error.message }));
    return true;
  }

  // Open sidebar and trigger enrichment (from fox icon click)
  if (message.type === 'open-sidebar-enrich') {
    // Open sidebar first
    browser.sidebarAction.open();

    // Store pending enrichment
    browser.storage.local.set({
      pendingEnrichment: {
        hash: message.hash,
        timestamp: Date.now()
      }
    }).then(() => {
      // Send message to sidebar after brief delay
      setTimeout(() => {
        try {
          browser.runtime.sendMessage({
            type: 'enrich-hash',
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
    browser.storage.local.get(['claudeApiKey', 'claudeModel', 'scanEnabled'])
      .then(result => sendResponse({
        hasApiKey: !!result.claudeApiKey,
        model: result.claudeModel || 'claude-sonnet-4-20250514',
        scanEnabled: result.scanEnabled !== false // Default to true
      }))
      .catch(error => sendResponse({ error: error.message }));
    return true;
  }
});

/**
 * Handle quick lookup for page scanning (JA4DB only, no Claude)
 */
async function handleQuickLookup(hash, type) {
  const cacheKey = `${type}:${hash}`;

  // Check cache first
  const cached = quickLookupCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.result;
  }

  // Check rate limit
  if (!rateLimiter.canMakeRequest()) {
    return {
      hash,
      type,
      error: 'Rate limit exceeded',
      rateLimited: true
    };
  }

  try {
    rateLimiter.recordRequest();

    // Parse the fingerprint
    const parsed = JA4Parser.parse(hash);

    // Check local known fingerprints
    const knownMatch = findKnownFingerprint(hash);

    // Query JA4DB only (no Claude for quick lookup)
    const ja4dbResult = await JA4DBClient.lookup(hash, type);

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

  // Query JA4 Database (ja4db.com)
  let ja4dbResult = null;
  try {
    console.log('JAH: Querying JA4 Database for', hash);
    ja4dbResult = await JA4DBClient.lookup(hash, parsed.type);
    console.log('JAH: JA4DB result:', ja4dbResult.found ? 'found' : 'not found');
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
