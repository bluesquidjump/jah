/**
 * JAH Content Script
 * Handles text selection detection, page scanning, and communication with background script
 */

(function() {
  'use strict';

  // Debug mode - set via storage or manually
  let DEBUG_MODE = false;

  function debug(...args) {
    if (DEBUG_MODE) {
      console.log('JAH DEBUG:', ...args);
    }
  }

  // JA4 patterns for detection (with word boundaries for scanning)
  const JA4_PATTERNS = {
    // JA4: TLS client fingerprint - t13d1516h2_8daaf6152771_b0da82dd1658
    JA4: /\b[tq][0-9]{2}[di][0-9]{4,6}[a-z0-9]{0,4}_[a-f0-9]{12}_[a-f0-9]{12}\b/gi,

    // JA4S: TLS server fingerprint - t130200_1301_234ea6891581 or t1203h1_c02f_f90b16d5c5e4
    // Updated to allow alphanumeric in first segment (some variants have h1, h2, etc.)
    JA4S: /\b[tq][0-9]{4,6}[a-z0-9]{0,2}_[a-f0-9]{4}_[a-f0-9]{12}\b/gi,

    // JA4H: HTTP client fingerprint - ge11cn20enus_60ca1bd65281_ac95b44401d9_8df6a44f726c
    JA4H: /\b[a-z]{2}[0-9]{2}[a-z]{2}[0-9]{2}[a-z]{4}_[a-f0-9]{12}_[a-f0-9]{12}_[a-f0-9]{12}\b/gi,

    // JA4SSH: SSH fingerprint - c76s56p21_i76o21
    JA4SSH: /\bc[0-9]{1,4}s[0-9]{1,4}p[0-9]{1,4}_[io][0-9]{1,4}[io][0-9]{1,4}\b/gi
  };

  // File hash patterns (order: longest first to avoid substring matches)
  const FILE_HASH_PATTERNS = {
    SHA256: /\b[a-f0-9]{64}\b/gi,
    SHA1: /\b[a-f0-9]{40}\b/gi,
    MD5: /\b[a-f0-9]{32}\b/gi
  };

  // Track hash candidates per page for threshold adjustment
  let hashCandidateCount = 0;

  // Simple patterns for selection detection (no word boundaries)
  const SELECTION_PATTERNS = [
    /[tq][0-9]{2}[di][0-9]{4,6}[a-z0-9]{0,4}_[a-f0-9]{12}_[a-f0-9]{12}/i,
    /[tq][0-9]{4,6}[a-z0-9]{0,2}_[a-f0-9]{4}_[a-f0-9]{12}/i,
    /[a-z]{2}[0-9]{2}[a-z]{2}[0-9]{2}[a-z]{4}_[a-f0-9]{12}_[a-f0-9]{12}_[a-f0-9]{12}/i,
    /[a-f0-9]{12}_[a-f0-9]{12}_[a-f0-9]{12}/i,
    /c[0-9]{1,4}s[0-9]{1,4}p[0-9]{1,4}_[io][0-9]{1,4}[io][0-9]{1,4}/i,
    /[0-9]+_[0-9\-]+_[0-9]+_[0-9]+/
  ];

  // Track processed nodes and hashes
  const processedNodes = new WeakSet();
  const processedHashes = new Map();

  // Stats for debugging
  const stats = {
    detected: 0,
    lookupAttempts: 0,
    lookupSuccesses: 0,
    rateLimited: 0,
    errors: 0
  };

  // Icon URLs
  const FOX_ICON_URL = browser.runtime.getURL('icons/ja4-fox-flag.png');
  const BUG_ICON_URL = browser.runtime.getURL('icons/hash-bug.svg');

  /**
   * Check if a detected type is a file hash
   */
  function isFileHashType(type) {
    return ['MD5', 'SHA1', 'SHA256'].includes(type);
  }

  /**
   * Score confidence that a hex string is actually a file hash (not a false positive)
   * Returns 0-100
   */
  function scoreHashConfidence(hexString, textNode) {
    let score = 0;
    const parentEl = textNode.parentNode;
    const text = textNode.textContent;
    const pageTitle = document.title.toLowerCase();
    const pageUrl = window.location.href.toLowerCase();

    // Gather surrounding text from multiple ancestor levels for context.
    // Walk up to 4 levels but cap text length to avoid matching entire page.
    let surroundingText = '';
    let ancestor = parentEl;
    for (let i = 0; i < 4 && ancestor && ancestor !== document.body; i++) {
      surroundingText = (ancestor.textContent || '').toLowerCase();
      // Stop once we have enough context (but not the whole page)
      if (surroundingText.length > 200) break;
      ancestor = ancestor.parentNode;
    }
    // Cap to 500 chars around the hash to avoid matching page-wide content
    const hashIdx = surroundingText.indexOf(hexString.toLowerCase());
    if (hashIdx > -1 && surroundingText.length > 500) {
      const ctxStart = Math.max(0, hashIdx - 200);
      const ctxEnd = Math.min(surroundingText.length, hashIdx + hexString.length + 200);
      surroundingText = surroundingText.substring(ctxStart, ctxEnd);
    }

    // Label patterns that indicate CTI/hash context
    // Note: "hash" alone is included but we separately check for git context to avoid
    // matching descriptions like "Git commit hash" in non-CTI contexts
    const ctiLabelPatterns = /\b(md5|sha256|sha1|sha-256|sha-1|ioc|indicator|sample|malware|checksum|file\s*hash|threat)\b/i;
    // Broader pattern including "hash" by itself
    const hashWordPattern = /\b(hash)\b/i;

    // --- Positive signals ---

    // Nearby text contains specific CTI labels (not just "hash" alone)
    if (ctiLabelPatterns.test(surroundingText)) {
      score += 30;
    } else if (hashWordPattern.test(surroundingText)) {
      // "hash" alone is weaker - only +15, and can be overridden by git context
      score += 15;
    }

    // Page URL/title contains CTI keywords
    const ctiKeywords = /\b(virustotal|malware|threat|ioc|abuse|malwarebazaar|hybrid-analysis|any\.run|sandbox|intel|security)\b/i;
    if (ctiKeywords.test(pageUrl) || ctiKeywords.test(pageTitle)) {
      score += 20;
    }

    // Inside semantic elements that suggest hash content
    let el = parentEl;
    for (let i = 0; i < 3 && el; i++) {
      const tag = el.tagName;
      if (tag === 'CODE' || tag === 'PRE' || tag === 'TD' || tag === 'SAMP' || tag === 'KBD') {
        score += 15;
        break;
      }
      const cls = (el.className || '').toLowerCase();
      if (cls.includes('hash') || cls.includes('ioc') || cls.includes('indicator') || cls.includes('fingerprint')) {
        score += 15;
        break;
      }
      el = el.parentNode;
    }

    // Multiple hash-length hex strings on the same page (IOC list signal)
    if (hashCandidateCount > 3) {
      score += 10;
    }

    // SHA256 length bonus (64 chars is much less likely to be a false positive)
    if (hexString.length === 64) {
      score += 10;
    }

    // --- Negative signals ---

    // UUID pattern (8-4-4-4-12 with dashes nearby)
    const uuidContext = text.substring(
      Math.max(0, text.indexOf(hexString) - 5),
      Math.min(text.length, text.indexOf(hexString) + hexString.length + 5)
    );
    if (/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i.test(surroundingText)) {
      score -= 100;
    }

    // CSS/color context
    if (/#[a-f0-9]{3,8}\b/i.test(uuidContext) ||
        /\b(color|background|border|rgb|hsl)\s*:/i.test(surroundingText)) {
      score -= 100;
    }

    // Inside <a href> or URL path
    if (parentEl?.tagName === 'A' && parentEl.href) {
      score -= 50;
    }
    if (/\/(api|v[0-9]|path|url|route)\//i.test(surroundingText)) {
      score -= 30;
    }

    // Git context — always penalize when git keywords are present,
    // unless strong CTI labels (not just "hash") are also present
    if (/\b(commit|merge|branch|git|rebase|cherry-pick)\b/i.test(surroundingText) &&
        !ctiLabelPatterns.test(surroundingText)) {
      score -= 50;
    }

    return Math.max(0, Math.min(100, score));
  }

  // ============================================
  // Utility Functions
  // ============================================

  /**
   * Escape HTML to prevent XSS
   */
  function escapeHtml(str) {
    if (!str || typeof str !== 'string') return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  /**
   * Validate category is one of allowed values
   */
  function validateCategory(category) {
    const allowed = ['browser', 'vpn', 'malware', 'tool', 'library', 'bot', 'suspicious', 'benign', 'unknown'];
    return allowed.includes(category) ? category : 'unknown';
  }

  /**
   * Detect fingerprint or file hash type
   */
  function detectType(hash) {
    if (!hash || typeof hash !== 'string') return null;
    const trimmed = hash.trim();

    // JA4 patterns first (more specific due to underscores and structured prefixes)
    // JA4: t13d1516h2_8daaf6152771_b0da82dd1658
    if (/^[tq][0-9]{2}[di][0-9]{4,6}[a-z0-9]{0,4}_[a-f0-9]{12}_[a-f0-9]{12}$/i.test(trimmed)) {
      return 'JA4';
    }
    // JA4S: t130200_1301_234ea6891581 or t1203h1_c02f_f90b16d5c5e4
    if (/^[tq][0-9]{4,6}[a-z0-9]{0,2}_[a-f0-9]{4}_[a-f0-9]{12}$/i.test(trimmed)) {
      return 'JA4S';
    }
    // JA4H: ge11cn20enus_60ca1bd65281_ac95b44401d9_8df6a44f726c
    if (/^[a-z]{2}[0-9]{2}[a-z]{2}[0-9]{2}[a-z]{4}_[a-f0-9]{12}_[a-f0-9]{12}_[a-f0-9]{12}$/i.test(trimmed)) {
      return 'JA4H';
    }
    // JA4SSH: c76s56p21_i76o21
    if (/^c[0-9]{1,4}s[0-9]{1,4}p[0-9]{1,4}_[io][0-9]{1,4}[io][0-9]{1,4}$/i.test(trimmed)) {
      return 'JA4SSH';
    }

    // File hash detection (longest first to avoid substring matches)
    if (/^[a-f0-9]{64}$/i.test(trimmed)) return 'SHA256';
    if (/^[a-f0-9]{40}$/i.test(trimmed)) return 'SHA1';
    if (/^[a-f0-9]{32}$/i.test(trimmed)) return 'MD5';

    return null;
  }

  /**
   * Check if text might be a JA4 fingerprint or file hash (for selection)
   */
  function mightBeJA4(text) {
    if (!text || text.length < 10 || text.length > 100) return false;
    const trimmed = text.trim();
    // JA4 fingerprints contain underscores
    if (trimmed.includes('_')) {
      return SELECTION_PATTERNS.some(pattern => pattern.test(trimmed));
    }
    // File hashes are pure hex of specific lengths
    if (/^[a-f0-9]{32}$/i.test(trimmed) ||
        /^[a-f0-9]{40}$/i.test(trimmed) ||
        /^[a-f0-9]{64}$/i.test(trimmed)) {
      return true;
    }
    return false;
  }

  /**
   * Extract JA4 hash from selection
   */
  function extractJA4FromSelection(text) {
    const trimmed = text.trim();
    for (const pattern of SELECTION_PATTERNS) {
      const match = trimmed.match(pattern);
      if (match) return match[0];
    }
    return trimmed;
  }

  // ============================================
  // Page Scanning Functions (from ottojah)
  // ============================================

  /**
   * Find all JA4 fingerprints and file hashes in text
   * @param {string} text - Text content to search
   * @param {Node} [textNode] - The text node (for confidence scoring)
   */
  function findFingerprints(text, textNode) {
    const results = [];
    const seen = new Set();
    const coveredRanges = [];

    // Helper to check if a position is already covered by a longer match
    function isRangeCovered(start, end) {
      return coveredRanges.some(r => start >= r.start && end <= r.end);
    }

    // JA4 patterns first (higher specificity)
    for (const [type, pattern] of Object.entries(JA4_PATTERNS)) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(text)) !== null) {
        const hash = match[0];
        const detectedType = detectType(hash);

        if (detectedType && !seen.has(hash.toLowerCase())) {
          seen.add(hash.toLowerCase());
          const range = { start: match.index, end: match.index + hash.length };
          coveredRanges.push(range);
          results.push({
            hash,
            type: detectedType,
            index: match.index,
            length: hash.length
          });
        }
      }
    }

    // File hash patterns (longest first: SHA256 -> SHA1 -> MD5)
    const hashThreshold = hashCandidateCount > 50 ? 60 : 30;
    for (const [type, pattern] of Object.entries(FILE_HASH_PATTERNS)) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(text)) !== null) {
        const hash = match[0];

        // Skip if this range is already covered by a JA4 match or a longer hash
        if (isRangeCovered(match.index, match.index + hash.length)) continue;
        if (seen.has(hash.toLowerCase())) continue;

        // Confidence scoring to reduce false positives
        if (textNode) {
          const confidence = scoreHashConfidence(hash, textNode);
          if (confidence < hashThreshold) {
            debug(`Skipping low-confidence hash (${confidence}): ${hash.substring(0, 16)}...`);
            continue;
          }
        }

        hashCandidateCount++;
        seen.add(hash.toLowerCase());
        const range = { start: match.index, end: match.index + hash.length };
        coveredRanges.push(range);
        results.push({
          hash,
          type,
          index: match.index,
          length: hash.length,
          isFileHash: true
        });
      }
    }

    results.sort((a, b) => a.index - b.index);
    return results;
  }

  // Known malware/suspicious application patterns
  const MALWARE_PATTERNS = [
    /sliver/i, /cobalt\s*strike/i, /metasploit/i, /meterpreter/i,
    /empire/i, /covenant/i, /brute\s*ratel/i, /havoc/i, /mythic/i,
    /pupy/i, /quasar/i, /njrat/i, /asyncrat/i, /remcos/i,
    /agent\s*tesla/i, /lokibot/i, /emotet/i, /trickbot/i,
    /qakbot/i, /icedid/i, /dridex/i, /ursnif/i, /zloader/i
  ];

  /**
   * Check if application name matches known malware
   */
  function isMalwareApplication(appName) {
    if (!appName) return false;
    return MALWARE_PATTERNS.some(pattern => pattern.test(appName));
  }

  /**
   * Determine category from result data
   * Priority: Claude assessment > local known match > JA4DB direct matches > JA4DB related matches
   */
  function determineCategory(result) {
    // 1. Check Claude's structured assessment first (highest priority)
    if (result.assessment && result.assessment.category) {
      return validateCategory(result.assessment.category);
    }

    // 2. Check known match from local database
    if (result.knownMatch && result.knownMatch.category) {
      return validateCategory(result.knownMatch.category);
    }

    // 3. Check JA4DB results with type-awareness
    const ja4db = result.ja4dbResult || result.ja4db;
    if (ja4db && ja4db.found) {
      // First check DIRECT applications (associated with the queried fingerprint type)
      const directApps = ja4db.summary?.directApplications || [];
      for (const app of directApps) {
        if (isMalwareApplication(app)) {
          return 'malware';
        }
      }

      // If no direct malware, check if direct apps suggest a benign category
      if (directApps.length > 0) {
        // Has direct applications but none are malware - likely legitimate
        return null; // Let the UI show neutral/unknown rather than incorrectly flagging
      }

      // Only check related applications if there are no direct applications
      // Related apps are associated with OTHER fingerprint types in the same record
      // (e.g., queried JA4S but the malware is identified by JA4 in the same record)
      const relatedApps = ja4db.summary?.relatedApplications || [];
      if (relatedApps.length > 0 && directApps.length === 0) {
        // Log for debugging - this is the case where we'd previously misattribute
        console.log('JAH: Found related (not direct) applications:', relatedApps);
        // Don't return malware category for related apps - the queried fingerprint
        // itself isn't directly associated with malware
      }

      // Fallback: check all applications if no direct/related distinction available
      // (for backward compatibility with cached results)
      if (!ja4db.summary?.directApplications && !ja4db.summary?.relatedApplications) {
        const allApps = ja4db.summary?.applications || [];
        for (const app of allApps) {
          if (isMalwareApplication(app)) {
            return 'malware';
          }
        }
      }
    }

    return null;
  }

  /**
   * Create the flag element (fox for JA4, bug for file hashes)
   */
  function createFoxFlag(hash, type, result) {
    const isHash = isFileHashType(type);

    const flag = document.createElement('span');
    flag.className = isHash ? 'jah-flag jah-file-hash' : 'jah-flag';
    flag.setAttribute('data-hash', hash);
    flag.setAttribute('data-type', type);

    const img = document.createElement('img');
    img.src = isHash ? BUG_ICON_URL : FOX_ICON_URL;
    img.alt = isHash ? 'File Hash' : 'JA4 Fingerprint';
    img.className = isHash ? 'jah-flag-img jah-bug-icon' : 'jah-fox-icon';
    flag.appendChild(img);

    // Create tooltip
    const tooltip = document.createElement('span');
    tooltip.className = 'jah-tooltip';

    // Check if we have any data about this fingerprint
    const hasJa4dbMatch = result.ja4db && result.ja4db.found;
    const hasKnownMatch = result.knownMatch;
    const hasAssessment = result.assessment;
    const hasThreatIntel = result.threatIntel;

    // Check for verified JA4DB records
    const ja4db = result.ja4db;
    const isVerified = ja4db && ja4db.summary && ja4db.summary.verifiedCount > 0;

    // Check for high-confidence LLM assessment
    const isHighConfidence = hasAssessment && result.assessment.confidence === 'high';

    // Determine category for styling
    const category = determineCategory(result);

    // Apply category styling if:
    // 1. We have a category from any source, OR
    // 2. JA4DB record is verified, OR
    // 3. LLM assessment has high confidence
    if (category) {
      flag.classList.add(`jah-category-${category}`);
    } else if (isVerified || isHighConfidence) {
      // Verified or high-confidence but no specific category - mark as verified/trusted
      flag.classList.add('jah-verified');
    } else if (!hasJa4dbMatch && !hasKnownMatch) {
      // No match found - mark as unverified
      flag.classList.add('jah-unverified');
    }

    // Build tooltip text
    if (hasAssessment && isHighConfidence) {
      // High confidence LLM assessment takes priority
      const categoryDisplay = result.assessment.category === 'benign' ? 'Legitimate' :
        result.assessment.category.charAt(0).toUpperCase() + result.assessment.category.slice(1);
      tooltip.textContent = `${categoryDisplay} (${result.assessment.confidence} confidence)`;
      flag.classList.add('jah-confident');
    } else if (hasKnownMatch) {
      tooltip.textContent = result.knownMatch.description ||
        `${result.knownMatch.name} (${result.knownMatch.category || 'unknown'})`;
    } else if (hasJa4dbMatch) {
      // Use DIRECT applications only (not related ones from other fingerprint types)
      const directApps = ja4db.summary?.directApplications || [];
      const relatedApps = ja4db.summary?.relatedApplications || [];

      if (directApps.length > 0) {
        tooltip.textContent = `Likely: ${directApps.slice(0, 2).join(' or ')}`;
        // Add warning for malware
        if (category === 'malware') {
          tooltip.textContent = `⚠ ${directApps[0]} (known malware)`;
        }
      } else if (relatedApps.length > 0) {
        // Show that this is a related fingerprint, not the application itself
        tooltip.textContent = `${type} seen with: ${relatedApps.slice(0, 2).join(', ')}`;
        // Add note that this is the server response, not the client
        if (type === 'JA4S') {
          tooltip.textContent = `Server response (client was ${relatedApps[0]})`;
        }
      } else {
        // Fallback to all applications if no direct/related distinction
        const allApps = ja4db.summary?.applications || [];
        if (allApps.length > 0) {
          tooltip.textContent = `Likely: ${allApps.slice(0, 2).join(' or ')}`;
        } else {
          tooltip.textContent = `Found in JA4DB (${ja4db.matchCount} matches)`;
        }
      }

      // Add verified indicator
      if (isVerified) {
        tooltip.textContent += ' ✓';
      }
    } else if (isHash && hasThreatIntel) {
      // File hash with threat intel results
      const vt = result.threatIntel.virusTotal;
      if (vt && vt.found) {
        tooltip.textContent = `${type} - ${vt.maliciousCount}/${vt.totalEngines} VT detections`;
      } else {
        tooltip.textContent = `${type} hash detected`;
      }
    } else if (result.rateLimited) {
      tooltip.textContent = `${type} detected (rate limited)`;
      flag.classList.add('jah-rate-limited');
    } else if (result.error) {
      tooltip.textContent = `${type} detected (lookup error)`;
      flag.classList.add('jah-error');
    } else if (isHash) {
      tooltip.textContent = `${type} hash detected`;
      flag.classList.add('jah-unverified');
    } else {
      tooltip.textContent = `${type} detected (not in JA4DB)`;
    }

    // Add "Click for full analysis" hint
    const hint = document.createElement('div');
    hint.className = 'jah-tooltip-hint';
    hint.textContent = 'Click for full analysis';
    tooltip.appendChild(hint);

    flag.appendChild(tooltip);

    // Click handler - show inline panel (sidebar can't be opened from content script)
    flag.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      showInlinePanel(flag, hash, type, result, isHash);
    });

    return flag;
  }

  // Track active inline panel
  let activePanel = null;

  /**
   * Show inline enrichment panel when icon is clicked
   */
  function showInlinePanel(flagElement, hash, type, cachedResult, isHash) {
    // Remove any existing panel
    if (activePanel) {
      activePanel.remove();
      activePanel = null;
    }

    // Create panel
    const panel = document.createElement('div');
    panel.className = 'jah-inline-panel';

    // Header
    const header = document.createElement('div');
    header.className = 'jah-panel-header';
    const headerTitle = isHash ? 'File Hash Analysis' : 'JA4 Analysis';
    header.innerHTML = `<strong>${headerTitle}</strong><span class="jah-panel-close">&times;</span>`;
    panel.appendChild(header);

    // Hash display
    const hashDiv = document.createElement('div');
    hashDiv.className = 'jah-panel-hash';
    hashDiv.textContent = hash;
    panel.appendChild(hashDiv);

    // Type badge
    const typeBadge = document.createElement('span');
    typeBadge.className = 'jah-panel-type';
    typeBadge.textContent = type;
    panel.appendChild(typeBadge);

    // Content area
    const content = document.createElement('div');
    content.className = 'jah-panel-content';
    content.innerHTML = '<div class="jah-panel-loading">Loading full analysis...</div>';
    panel.appendChild(content);

    // Position and add to DOM
    document.body.appendChild(panel);
    activePanel = panel;

    // Position near the flag
    const rect = flagElement.getBoundingClientRect();
    const panelRect = panel.getBoundingClientRect();
    let left = rect.left + window.scrollX;
    let top = rect.bottom + window.scrollY + 8;

    // Adjust if off-screen
    if (left + panelRect.width > window.innerWidth) {
      left = window.innerWidth - panelRect.width - 20;
    }
    if (top + panelRect.height > window.innerHeight + window.scrollY) {
      top = rect.top + window.scrollY - panelRect.height - 8;
    }

    panel.style.left = `${Math.max(10, left)}px`;
    panel.style.top = `${top}px`;

    // Close button handler
    header.querySelector('.jah-panel-close').addEventListener('click', () => {
      panel.remove();
      activePanel = null;
    });

    // Close on click outside
    setTimeout(() => {
      document.addEventListener('click', function closePanel(e) {
        if (!panel.contains(e.target) && !flagElement.contains(e.target)) {
          panel.remove();
          activePanel = null;
          document.removeEventListener('click', closePanel);
        }
      });
    }, 100);

    // Display cached result immediately if available
    if (cachedResult) {
      displayPanelResult(content, cachedResult, hash);
    }

    // Request full enrichment from background
    const enrichType = isHash ? 'enrich-file-hash' : 'enrich-hash';
    browser.runtime.sendMessage({
      type: enrichType,
      hash: hash,
      fingerprintType: type
    }).then(result => {
      if (result.success) {
        displayPanelResult(content, result, hash);
      } else {
        content.innerHTML = `<div class="jah-panel-error">Error: ${escapeHtml(result.error || 'Unknown error')}</div>`;
      }
    }).catch(error => {
      content.innerHTML = `<div class="jah-panel-error">Error: ${escapeHtml(error.message)}</div>`;
    });
  }

  /**
   * Display enrichment result in panel
   */
  function displayPanelResult(container, result, hash) {
    const category = determineCategory(result);
    let html = '';

    // Category indicator
    if (category) {
      const categoryClass = category === 'malware' ? 'jah-panel-malware' : `jah-panel-${category}`;
      html += `<div class="jah-panel-category ${categoryClass}">${category.toUpperCase()}</div>`;
    }

    // Known match info
    if (result.knownMatch) {
      html += `<div class="jah-panel-section">
        <div class="jah-panel-label">Identified As:</div>
        <div class="jah-panel-value">${escapeHtml(result.knownMatch.name)}</div>
        <div class="jah-panel-desc">${escapeHtml(result.knownMatch.description || '')}</div>
      </div>`;
    }

    // VirusTotal results (for file hashes)
    const vt = result.threatIntel?.virusTotal;
    if (vt && vt.found) {
      html += `<div class="jah-panel-section">
        <div class="jah-panel-label">VirusTotal:</div>
        <div class="jah-panel-value">${vt.maliciousCount}/${vt.totalEngines} engines detected</div>
      </div>`;
    }

    // MalwareBazaar results (for file hashes)
    const mb = result.threatIntel?.malwareBazaar;
    if (mb && mb.found && mb.signature) {
      html += `<div class="jah-panel-section">
        <div class="jah-panel-label">Malware Family:</div>
        <div class="jah-panel-value">${escapeHtml(mb.signature)}</div>
      </div>`;
    }

    // JA4DB results
    if (result.ja4dbResult?.found || result.ja4db?.found) {
      const db = result.ja4dbResult || result.ja4db;
      const apps = db.summary?.applications || [];
      if (apps.length > 0) {
        html += `<div class="jah-panel-section">
          <div class="jah-panel-label">JA4DB Applications:</div>
          <div class="jah-panel-value">${apps.map(a => escapeHtml(a)).join(', ')}</div>
        </div>`;
      }
      html += `<div class="jah-panel-section">
        <div class="jah-panel-label">Database:</div>
        <div class="jah-panel-value">${db.matchCount || 0} matches, ${db.summary?.totalObservations || 0} observations</div>
      </div>`;
    }

    // Claude analysis summary
    if (result.summary) {
      html += `<div class="jah-panel-section">
        <div class="jah-panel-label">Analysis:</div>
        <div class="jah-panel-value">${escapeHtml(result.summary)}</div>
      </div>`;
    }

    // Sidebar hint
    html += `<div class="jah-panel-footer">
      <span class="jah-panel-footer-icon">📋</span>
      <span class="jah-panel-sidebar-hint">
        <strong>Full details:</strong> Open JAH sidebar via View → Sidebar → JAH
      </span>
    </div>`;

    container.innerHTML = html;

    // Store pending enrichment so sidebar picks it up when opened
    browser.runtime.sendMessage({
      type: 'open-sidebar-enrich',
      hash: hash
    }).catch(() => {});
  }

  /**
   * Process a text node and wrap JA4 fingerprints with flags
   */
  async function processTextNode(textNode) {
    if (processedNodes.has(textNode)) return;

    const text = textNode.textContent;
    const fingerprints = findFingerprints(text, textNode);

    if (fingerprints.length === 0) return;

    debug(`Found ${fingerprints.length} fingerprints in text node`);
    stats.detected += fingerprints.length;

    processedNodes.add(textNode);

    const fragment = document.createDocumentFragment();
    let lastIndex = 0;

    for (const fp of fingerprints) {
      // Add text before this fingerprint
      if (fp.index > lastIndex) {
        fragment.appendChild(document.createTextNode(text.substring(lastIndex, fp.index)));
      }

      // Create wrapper span for the fingerprint
      const wrapper = document.createElement('span');
      wrapper.className = 'jah-fingerprint';
      wrapper.textContent = fp.hash;

      // Check cache first
      let result = processedHashes.get(fp.hash.toLowerCase());

      if (!result) {
        stats.lookupAttempts++;
        debug(`Looking up: ${fp.hash} (${fp.type})`);

        // Add loading indicator
        const loadingFlag = document.createElement('span');
        loadingFlag.className = 'jah-flag jah-loading';
        loadingFlag.innerHTML = '<span class="jah-spinner"></span>';
        wrapper.appendChild(loadingFlag);

        // Perform quick lookup (JA4DB for JA4, known-fingerprints for hashes)
        const lookupType = fp.isFileHash ? 'quick-lookup-hash' : 'quick-lookup';
        browser.runtime.sendMessage({
          type: lookupType,
          hash: fp.hash,
          fingerprintType: fp.type
        }).then(lookupResult => {
          processedHashes.set(fp.hash.toLowerCase(), lookupResult);
          loadingFlag.remove();

          // Check for rate limiting or errors
          if (lookupResult.rateLimited) {
            stats.rateLimited++;
            debug(`Rate limited: ${fp.hash}`);
          } else if (lookupResult.error) {
            stats.errors++;
            debug(`Error for ${fp.hash}: ${lookupResult.error}`);
          }

          // Always add fox flag for detected fingerprints
          // Color/style will indicate whether JA4DB had a match
          const flag = createFoxFlag(fp.hash, fp.type, lookupResult);
          wrapper.appendChild(flag);

          if (lookupResult.ja4db && lookupResult.ja4db.found) {
            stats.lookupSuccesses++;
            debug(`JA4DB match: ${fp.hash}`);
          } else {
            debug(`No JA4DB match: ${fp.hash}`);
          }
        }).catch(error => {
          stats.errors++;
          console.error('JAH lookup error:', error);
          loadingFlag.remove();
        });
      } else {
        // Use cached result - always show fox icon
        const flag = createFoxFlag(fp.hash, fp.type, result);
        wrapper.appendChild(flag);
      }

      fragment.appendChild(wrapper);
      lastIndex = fp.index + fp.length;
    }

    // Add remaining text
    if (lastIndex < text.length) {
      fragment.appendChild(document.createTextNode(text.substring(lastIndex)));
    }

    // Replace the original text node
    if (textNode.parentNode) {
      textNode.parentNode.replaceChild(fragment, textNode);
    }
  }

  /**
   * Walk DOM and find text nodes to process
   */
  function walkDOM(node) {
    const skipTags = ['SCRIPT', 'STYLE', 'NOSCRIPT', 'IFRAME', 'TEXTAREA', 'INPUT', 'SELECT'];
    if (skipTags.includes(node.nodeName)) return;

    // Skip already processed elements
    if (node.classList && (
      node.classList.contains('jah-fingerprint') ||
      node.classList.contains('jah-flag') ||
      node.classList.contains('jah-tooltip')
    )) return;

    if (node.nodeType === Node.TEXT_NODE) {
      const text = node.textContent;
      // Check for JA4 fingerprints (contain underscores) or file hashes (32+ hex chars)
      if ((text.includes('_') && text.length > 12) ||
          (text.length >= 32 && /[a-f0-9]{32}/i.test(text))) {
        processTextNode(node);
      }
    } else if (node.nodeType === Node.ELEMENT_NODE) {
      const children = Array.from(node.childNodes);
      for (const child of children) {
        walkDOM(child);
      }
    }
  }

  // ============================================
  // Selection Detection (original JAH)
  // ============================================

  let lastSelection = '';
  let tooltipElement = null;

  function createTooltip() {
    if (tooltipElement) return tooltipElement;

    tooltipElement = document.createElement('div');
    tooltipElement.id = 'jah-selection-tooltip';
    tooltipElement.style.cssText = `
      position: fixed;
      background: #004b87;
      color: #ffffff;
      padding: 6px 12px;
      border-radius: 2px;
      font-size: 12px;
      font-family: -apple-system, BlinkMacSystemFont, 'Helvetica Neue', Arial, sans-serif;
      z-index: 999999;
      pointer-events: none;
      opacity: 0;
      transition: opacity 0.2s;
      box-shadow: 0 2px 8px rgba(0, 75, 135, 0.3);
      border: none;
      letter-spacing: 0.5px;
    `;
    document.body.appendChild(tooltipElement);
    return tooltipElement;
  }

  function showTooltip(text, x, y) {
    const tooltip = createTooltip();
    tooltip.textContent = text;
    tooltip.style.left = `${x}px`;
    tooltip.style.top = `${y - 30}px`;
    tooltip.style.opacity = '1';

    setTimeout(() => {
      tooltip.style.opacity = '0';
    }, 2000);
  }

  function hideTooltip() {
    if (tooltipElement) {
      tooltipElement.style.opacity = '0';
    }
  }

  document.addEventListener('selectionchange', () => {
    const selection = window.getSelection();
    const selectedText = selection?.toString() || '';

    if (selectedText === lastSelection) return;
    lastSelection = selectedText;

    if (selectedText && mightBeJA4(selectedText)) {
      const range = selection.getRangeAt(0);
      const rect = range.getBoundingClientRect();

      browser.runtime.sendMessage({
        type: 'check-hash',
        hash: extractJA4FromSelection(selectedText)
      }).then(response => {
        if (response?.isValid) {
          const parsedType = response.parsed?.type || 'fingerprint';
          const isHash = isFileHashType(parsedType);
          const label = isHash ? `${parsedType} file hash` : `JA4 ${parsedType}`;
          showTooltip(`${label} detected - right-click to enrich`, rect.left, rect.top);
        }
      }).catch(() => {});
    } else {
      hideTooltip();
    }
  });

  // ============================================
  // Message Handling
  // ============================================

  browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'get-selection') {
      const selection = window.getSelection()?.toString() || '';
      sendResponse({ selection: extractJA4FromSelection(selection) });
    }
  });

  // ============================================
  // Initialization
  // ============================================

  async function init() {
    // Check if scanning is enabled and load debug mode
    const settings = await browser.runtime.sendMessage({ type: 'get-settings' }).catch(() => ({}));
    if (settings.scanEnabled === false) {
      console.log('JAH page scanning disabled');
      return;
    }

    // Enable debug mode if set in storage
    DEBUG_MODE = settings.debugMode === true;

    console.log('JAH scanner initializing...' + (DEBUG_MODE ? ' (DEBUG MODE)' : ''));

    // Initial page scan
    walkDOM(document.body);

    // Report stats after initial scan (with delay to let lookups complete)
    if (DEBUG_MODE) {
      setTimeout(() => {
        console.log('JAH STATS:', JSON.stringify(stats, null, 2));
      }, 5000);
    }

    // Expose debug functions to window for console access
    window.JAH_DEBUG = {
      getStats: () => stats,
      enableDebug: () => { DEBUG_MODE = true; console.log('JAH debug mode enabled'); },
      disableDebug: () => { DEBUG_MODE = false; console.log('JAH debug mode disabled'); },
      getProcessedHashes: () => Array.from(processedHashes.keys()),
      rescan: () => { walkDOM(document.body); console.log('JAH rescan complete'); }
    };
    debug('Debug functions available at window.JAH_DEBUG');

    // Watch for dynamic content
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE) {
            walkDOM(node);
          } else if (node.nodeType === Node.TEXT_NODE) {
            const text = node.textContent;
            if ((text.includes('_') && text.length > 12) ||
                (text.length >= 32 && /[a-f0-9]{32}/i.test(text))) {
              processTextNode(node);
            }
          }
        }
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });

    console.log('JAH scanner ready');
  }

  // Start when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  console.log('JAH Content script loaded');
})();
