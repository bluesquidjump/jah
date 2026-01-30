/**
 * JAH Content Script
 * Handles text selection detection, page scanning, and communication with background script
 */

(function() {
  'use strict';

  // JA4 patterns for detection (with word boundaries for scanning)
  const JA4_PATTERNS = {
    // JA4: TLS client fingerprint - t13d1516h2_8daaf6152771_b0da82dd1658
    JA4: /\b[tq][0-9]{2}[di][0-9]{4,6}[a-z0-9]{0,4}_[a-f0-9]{12}_[a-f0-9]{12}\b/gi,

    // JA4S: TLS server fingerprint - t130200_1301_234ea6891581
    JA4S: /\b[tq][0-9]{6}_[a-f0-9]{4}_[a-f0-9]{12}\b/gi,

    // JA4H: HTTP client fingerprint - ge11cn20enus_60ca1bd65281_ac95b44401d9_8df6a44f726c
    JA4H: /\b[a-z]{2}[0-9]{2}[a-z]{2}[0-9]{2}[a-z]{4}_[a-f0-9]{12}_[a-f0-9]{12}_[a-f0-9]{12}\b/gi,

    // JA4SSH: SSH fingerprint - c76s56p21_i76o21
    JA4SSH: /\bc[0-9]{1,4}s[0-9]{1,4}p[0-9]{1,4}_[io][0-9]{1,4}[io][0-9]{1,4}\b/gi
  };

  // Simple patterns for selection detection (no word boundaries)
  const SELECTION_PATTERNS = [
    /[tq][0-9]{2}[di][0-9]{4,6}[a-z0-9]{0,4}_[a-f0-9]{12}_[a-f0-9]{12}/i,
    /[tq][0-9]{6}_[a-f0-9]{4}_[a-f0-9]{12}/i,
    /[a-z]{2}[0-9]{2}[a-z]{2}[0-9]{2}[a-z]{4}_[a-f0-9]{12}_[a-f0-9]{12}_[a-f0-9]{12}/i,
    /[a-f0-9]{12}_[a-f0-9]{12}_[a-f0-9]{12}/i,
    /c[0-9]{1,4}s[0-9]{1,4}p[0-9]{1,4}_[io][0-9]{1,4}[io][0-9]{1,4}/i,
    /[0-9]+_[0-9\-]+_[0-9]+_[0-9]+/
  ];

  // Track processed nodes and hashes
  const processedNodes = new WeakSet();
  const processedHashes = new Map();

  // Fox icon URL
  const FOX_ICON_URL = browser.runtime.getURL('icons/ja4-fox-flag.png');

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
   * Detect JA4 fingerprint type
   */
  function detectType(hash) {
    if (!hash || typeof hash !== 'string') return null;
    const trimmed = hash.trim();

    if (/^[tq][0-9]{2}[di][0-9]{4,6}[a-z0-9]{0,4}_[a-f0-9]{12}_[a-f0-9]{12}$/i.test(trimmed)) {
      return 'JA4';
    }
    if (/^[tq][0-9]{6}_[a-f0-9]{4}_[a-f0-9]{12}$/i.test(trimmed)) {
      return 'JA4S';
    }
    if (/^[a-z]{2}[0-9]{2}[a-z]{2}[0-9]{2}[a-z]{4}_[a-f0-9]{12}_[a-f0-9]{12}_[a-f0-9]{12}$/i.test(trimmed)) {
      return 'JA4H';
    }
    if (/^c[0-9]{1,4}s[0-9]{1,4}p[0-9]{1,4}_[io][0-9]{1,4}[io][0-9]{1,4}$/i.test(trimmed)) {
      return 'JA4SSH';
    }
    return null;
  }

  /**
   * Check if text might be a JA4 fingerprint (for selection)
   */
  function mightBeJA4(text) {
    if (!text || text.length < 10 || text.length > 100) return false;
    const trimmed = text.trim();
    if (!trimmed.includes('_')) return false;
    return SELECTION_PATTERNS.some(pattern => pattern.test(trimmed));
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
   * Find all JA4 fingerprints in text
   */
  function findFingerprints(text) {
    const results = [];
    const seen = new Set();

    for (const [type, pattern] of Object.entries(JA4_PATTERNS)) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(text)) !== null) {
        const hash = match[0];
        const detectedType = detectType(hash);

        if (detectedType && !seen.has(hash.toLowerCase())) {
          seen.add(hash.toLowerCase());
          results.push({
            hash,
            type: detectedType,
            index: match.index,
            length: hash.length
          });
        }
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
   * Create the fox flag element
   */
  function createFoxFlag(hash, type, result) {
    const flag = document.createElement('span');
    flag.className = 'jah-flag';
    flag.setAttribute('data-hash', hash);
    flag.setAttribute('data-type', type);

    const img = document.createElement('img');
    img.src = FOX_ICON_URL;
    img.alt = 'JA4 Match';
    img.className = 'jah-fox-icon';
    flag.appendChild(img);

    // Create tooltip
    const tooltip = document.createElement('span');
    tooltip.className = 'jah-tooltip';

    // Determine category for styling
    const category = determineCategory(result);
    if (category) {
      flag.classList.add(`jah-category-${category}`);
    }

    if (result.analysis && result.analysis.confident) {
      tooltip.textContent = result.analysis.description ||
        `${result.analysis.application || 'Unknown'} (${result.analysis.category || 'unknown'})`;
      flag.classList.add('jah-confident');
    } else if (result.knownMatch) {
      tooltip.textContent = result.knownMatch.description ||
        `${result.knownMatch.name} (${result.knownMatch.category || 'unknown'})`;
    } else if (result.ja4db && result.ja4db.found) {
      const apps = result.ja4db.summary?.applications || [];
      if (apps.length > 0) {
        tooltip.textContent = `Likely: ${apps.slice(0, 2).join(' or ')}`;
        // Add warning for malware
        if (category === 'malware') {
          tooltip.textContent = `⚠ ${apps[0]} (known malware)`;
        }
      } else {
        tooltip.textContent = `Found in JA4DB (${result.ja4db.matchCount} matches)`;
      }
    } else {
      tooltip.textContent = 'JA4 fingerprint detected';
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
      showInlinePanel(flag, hash, type, result);
    });

    return flag;
  }

  // Track active inline panel
  let activePanel = null;

  /**
   * Show inline enrichment panel when fox icon is clicked
   */
  function showInlinePanel(flagElement, hash, type, cachedResult) {
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
    header.innerHTML = `<strong>JA4 Analysis</strong><span class="jah-panel-close">&times;</span>`;
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
    browser.runtime.sendMessage({
      type: 'enrich-hash',
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
    const fingerprints = findFingerprints(text);

    if (fingerprints.length === 0) return;

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
        // Add loading indicator
        const loadingFlag = document.createElement('span');
        loadingFlag.className = 'jah-flag jah-loading';
        loadingFlag.innerHTML = '<span class="jah-spinner"></span>';
        wrapper.appendChild(loadingFlag);

        // Perform quick lookup (JA4DB only, no Claude)
        browser.runtime.sendMessage({
          type: 'quick-lookup',
          hash: fp.hash,
          fingerprintType: fp.type
        }).then(lookupResult => {
          processedHashes.set(fp.hash.toLowerCase(), lookupResult);
          loadingFlag.remove();

          // Add fox flag if we have a match
          if (lookupResult.ja4db && lookupResult.ja4db.found) {
            const flag = createFoxFlag(fp.hash, fp.type, lookupResult);
            wrapper.appendChild(flag);
          }
        }).catch(error => {
          console.error('JAH lookup error:', error);
          loadingFlag.remove();
        });
      } else {
        // Use cached result
        if (result.ja4db && result.ja4db.found) {
          const flag = createFoxFlag(fp.hash, fp.type, result);
          wrapper.appendChild(flag);
        }
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
      if (text.includes('_') && text.length > 12) {
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
          showTooltip(`JA4 ${response.parsed?.type || 'fingerprint'} detected - right-click to enrich`, rect.left, rect.top);
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
    // Check if scanning is enabled
    const settings = await browser.runtime.sendMessage({ type: 'get-settings' }).catch(() => ({}));
    if (settings.scanEnabled === false) {
      console.log('JAH page scanning disabled');
      return;
    }

    console.log('JAH scanner initializing...');

    // Initial page scan
    walkDOM(document.body);

    // Watch for dynamic content
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE) {
            walkDOM(node);
          } else if (node.nodeType === Node.TEXT_NODE) {
            const text = node.textContent;
            if (text.includes('_') && text.length > 12) {
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
