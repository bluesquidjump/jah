/**
 * JAH Sidebar Script
 * Handles UI state and displays enrichment results
 */

(function() {
  'use strict';

  // UI Elements
  const elements = {
    initialState: document.getElementById('initial-state'),
    loadingState: document.getElementById('loading-state'),
    errorState: document.getElementById('error-state'),
    resultsState: document.getElementById('results-state'),
    loadingHash: document.getElementById('loading-hash'),
    loadingSteps: {
      parse: document.getElementById('step-parse'),
      ja4db: document.getElementById('step-ja4db'),
      analyze: document.getElementById('step-analyze')
    },
    errorText: document.getElementById('error-text'),
    retryBtn: document.getElementById('retry-btn'),
    resultType: document.getElementById('result-type'),
    resultTimestamp: document.getElementById('result-timestamp'),
    resultHash: document.getElementById('result-hash'),
    copyHash: document.getElementById('copy-hash'),
    summarySection: document.getElementById('summary-section'),
    summaryText: document.getElementById('summary-text'),
    ja4dbSection: document.getElementById('ja4db-section'),
    ja4dbContent: document.getElementById('ja4db-content'),
    knownMatch: document.getElementById('known-match'),
    knownMatchName: document.getElementById('known-match-name'),
    knownMatchDescription: document.getElementById('known-match-description'),
    parsedComponents: document.getElementById('parsed-components'),
    componentsList: document.getElementById('components-list'),
    analysisContent: document.getElementById('analysis-content'),
    mcpSection: document.getElementById('mcp-section'),
    mcpContent: document.getElementById('mcp-content'),
    modelInfo: document.getElementById('model-info'),
    usageInfo: document.getElementById('usage-info'),
    historyToggle: document.getElementById('history-toggle'),
    historyIcon: document.getElementById('history-icon'),
    historyContent: document.getElementById('history-content'),
    historyList: document.getElementById('history-list'),
    clearHistory: document.getElementById('clear-history'),
    settingsBtn: document.getElementById('settings-btn')
  };

  // Current state
  let currentHash = null;
  let historyExpanded = false;
  let isEnriching = false;

  /**
   * Show a specific state panel
   */
  function showState(stateName) {
    const states = ['initial', 'loading', 'error', 'results'];
    states.forEach(state => {
      const el = document.getElementById(`${state}-state`);
      if (el) {
        el.classList.toggle('hidden', state !== stateName);
      }
    });
  }

  /**
   * Update loading step status
   */
  function updateLoadingStep(step, status) {
    const stepEl = elements.loadingSteps[step];
    if (!stepEl) return;

    stepEl.classList.remove('active', 'complete', 'error');
    if (status) {
      stepEl.classList.add(status);
    }
  }

  /**
   * Format timestamp for display
   */
  function formatTimestamp(isoString) {
    const date = new Date(isoString);
    return date.toLocaleString();
  }

  /**
   * Render the summary section with optional assessment badge
   */
  function renderSummary(summary, assessment) {
    if (!summary) {
      elements.summarySection.classList.add('hidden');
      return;
    }

    elements.summarySection.classList.remove('hidden');
    elements.summaryText.textContent = summary;

    // Add assessment badge if available
    const existingBadge = elements.summarySection.querySelector('.assessment-badge');
    if (existingBadge) {
      existingBadge.remove();
    }

    if (assessment) {
      const badge = document.createElement('div');
      badge.className = `assessment-badge threat-${assessment.threatLevel} confidence-${assessment.confidence}`;

      // Map category to display-friendly name
      const categoryDisplay = assessment.category === 'benign' ? 'Legitimate' :
                             assessment.category.charAt(0).toUpperCase() + assessment.category.slice(1);

      badge.innerHTML = `
        <span class="assessment-category category-${assessment.category}">${escapeHtml(categoryDisplay)}</span>
        <span class="assessment-threat">Threat: ${escapeHtml(assessment.threatLevel)}</span>
        <span class="assessment-confidence">Confidence: ${escapeHtml(assessment.confidence)}</span>
      `;
      elements.summarySection.insertBefore(badge, elements.summaryText);
    }
  }

  /**
   * Render JA4 Database results
   */
  function renderJA4DBResults(ja4dbResult) {
    if (!ja4dbResult || !ja4dbResult.found) {
      elements.ja4dbSection.classList.add('hidden');
      return;
    }

    elements.ja4dbSection.classList.remove('hidden');

    const summary = ja4dbResult.summary;
    let html = '<div class="ja4db-summary">';

    // Match count badge
    html += `<div class="ja4db-badge">
      <span class="badge-count">${ja4dbResult.matchCount}</span>
      <span class="badge-label">record${ja4dbResult.matchCount !== 1 ? 's' : ''} found</span>
    </div>`;

    // Direct Applications (associated with the queried fingerprint type)
    if (summary.directApplications && summary.directApplications.length > 0) {
      html += `<div class="ja4db-item">
        <span class="ja4db-label">Applications:</span>
        <span class="ja4db-value">${summary.directApplications.map(escapeHtml).join(', ')}</span>
      </div>`;
    }

    // Related Applications (associated with other fingerprint types in the same record)
    if (summary.relatedApplications && summary.relatedApplications.length > 0) {
      html += `<div class="ja4db-item ja4db-related">
        <span class="ja4db-label">Related (different fingerprint type):</span>
        <span class="ja4db-value ja4db-related-value">${summary.relatedApplications.map(escapeHtml).join(', ')}</span>
        <div class="ja4db-related-note">These applications are identified by a different fingerprint type in the same database record.</div>
      </div>`;
    }

    // Fallback for older cached results without direct/related distinction
    if (!summary.directApplications && !summary.relatedApplications && summary.applications && summary.applications.length > 0) {
      html += `<div class="ja4db-item">
        <span class="ja4db-label">Applications:</span>
        <span class="ja4db-value">${summary.applications.map(escapeHtml).join(', ')}</span>
      </div>`;
    }

    // Libraries
    if (summary.libraries.length > 0) {
      html += `<div class="ja4db-item">
        <span class="ja4db-label">Libraries:</span>
        <span class="ja4db-value">${summary.libraries.map(escapeHtml).join(', ')}</span>
      </div>`;
    }

    // Operating Systems
    if (summary.operatingSystems.length > 0) {
      html += `<div class="ja4db-item">
        <span class="ja4db-label">OS:</span>
        <span class="ja4db-value">${summary.operatingSystems.map(escapeHtml).join(', ')}</span>
      </div>`;
    }

    // Devices
    if (summary.devices.length > 0) {
      html += `<div class="ja4db-item">
        <span class="ja4db-label">Devices:</span>
        <span class="ja4db-value">${summary.devices.map(escapeHtml).join(', ')}</span>
      </div>`;
    }

    // Verification status
    html += `<div class="ja4db-item">
      <span class="ja4db-label">Verified:</span>
      <span class="ja4db-value">${summary.verifiedCount} of ${summary.totalRecords}</span>
    </div>`;

    // Observations
    html += `<div class="ja4db-item">
      <span class="ja4db-label">Observations:</span>
      <span class="ja4db-value">${summary.totalObservations.toLocaleString()}</span>
    </div>`;

    // Sample user agents
    if (summary.userAgents && summary.userAgents.length > 0) {
      html += `<div class="ja4db-useragents">
        <span class="ja4db-label">Sample User Agents:</span>
        <ul>`;
      summary.userAgents.slice(0, 3).forEach(ua => {
        html += `<li><code>${escapeHtml(ua)}</code></li>`;
      });
      html += `</ul></div>`;
    }

    html += '</div>';
    elements.ja4dbContent.innerHTML = html;
  }

  /**
   * Render parsed components
   */
  function renderComponents(parsed) {
    if (!parsed?.components) {
      elements.parsedComponents.classList.add('hidden');
      return;
    }

    elements.parsedComponents.classList.remove('hidden');

    const componentLabels = {
      protocol: 'Protocol',
      tlsVersion: 'TLS Version',
      sniPresent: 'SNI Type',
      cipherCount: 'Cipher Count',
      extensionCount: 'Extension Count',
      alpn: 'ALPN',
      cipherHash: 'Cipher Hash',
      extensionHash: 'Extension Hash',
      chosenCipher: 'Chosen Cipher',
      httpMethod: 'HTTP Method',
      httpVersion: 'HTTP Version',
      hasCookie: 'Has Cookie',
      hasReferer: 'Has Referer',
      headerCount: 'Header Count',
      acceptLanguage: 'Accept-Language',
      headerHash: 'Header Hash',
      cookieHash: 'Cookie Hash',
      headerValueHash: 'Header Value Hash',
      issuerHash: 'Issuer Hash',
      subjectHash: 'Subject Hash',
      clientPackets: 'Client Packets',
      serverPackets: 'Server Packets',
      payloadSize: 'Payload Size',
      windowSize: 'Window Size',
      tcpOptions: 'TCP Options',
      mss: 'MSS',
      windowScale: 'Window Scale'
    };

    let html = '<dl class="components-dl">';
    for (const [key, value] of Object.entries(parsed.components)) {
      const label = componentLabels[key] || key;
      const displayValue = typeof value === 'boolean' ? (value ? 'Yes' : 'No') : value;
      html += `<dt>${label}</dt><dd>${escapeHtml(String(displayValue))}</dd>`;
    }
    html += '</dl>';

    // Add SSH interactivity analysis if present
    if (parsed.analysis?.isInteractive) {
      html += `<div class="ssh-analysis">
        <strong>Session Type:</strong> ${escapeHtml(parsed.analysis.isInteractive)}
      </div>`;
    }

    elements.componentsList.innerHTML = html;
  }

  /**
   * Render known match information
   */
  function renderKnownMatch(match) {
    if (!match) {
      elements.knownMatch.classList.add('hidden');
      return;
    }

    elements.knownMatch.classList.remove('hidden');
    elements.knownMatchName.textContent = match.name;
    elements.knownMatchDescription.textContent = match.description || '';

    // Add category styling
    const badge = elements.knownMatch.querySelector('.match-badge');
    badge.className = `match-badge category-${match.category || 'unknown'}`;
  }

  /**
   * Render MCP context results
   */
  function renderMCPContext(mcpContext) {
    if (!mcpContext || mcpContext.sources.length === 0) {
      elements.mcpSection.classList.add('hidden');
      return;
    }

    elements.mcpSection.classList.remove('hidden');

    let html = '';

    // Brave Search results
    if (mcpContext.data.braveSearch) {
      const search = mcpContext.data.braveSearch;
      html += `<div class="mcp-source">
        <h4>Web Search Results</h4>
        <ul class="search-results">`;
      search.results.forEach(r => {
        html += `<li>
          <a href="${escapeHtml(r.url)}" target="_blank">${escapeHtml(r.title)}</a>
          <p>${escapeHtml(r.description || '')}</p>
        </li>`;
      });
      html += '</ul></div>';
    }

    // Threat Intel results
    if (mcpContext.data.threatIntel) {
      const ti = mcpContext.data.threatIntel;

      if (ti.virusTotal) {
        html += `<div class="mcp-source">
          <h4>VirusTotal</h4>
          <p>Found ${ti.virusTotal.matchCount} related sample(s)</p>
        </div>`;
      }

      if (ti.shodan) {
        html += `<div class="mcp-source">
          <h4>Shodan</h4>
          <p>Found ${ti.shodan.total} host(s) with this fingerprint</p>
        </div>`;
      }
    }

    // Show errors if any
    if (mcpContext.errors.length > 0) {
      html += `<div class="mcp-errors">
        <small>Some integrations failed: ${mcpContext.errors.map(e => escapeHtml(e.source)).join(', ')}</small>
      </div>`;
    }

    elements.mcpContent.innerHTML = html;
  }

  /**
   * Render analysis content with markdown-like formatting
   * Uses safe markdown parsing that escapes HTML first
   */
  function renderAnalysis(analysisText) {
    if (!analysisText) {
      elements.analysisContent.innerHTML = '<p>No analysis available.</p>';
      return;
    }

    // Remove the summary section and ASSESSMENT line from the analysis since we display them separately
    let cleanedText = analysisText
      .replace(/^##?\s*Summary\s*\n+[\s\S]*?(?=\n##?\s|\n\*\*[A-Z])/im, '')
      .replace(/\n*ASSESSMENT:\s*\w+\s*\|\s*\w+\s*\|\s*\w+\s*$/im, '')
      .trim();

    // SECURITY: Escape HTML first to prevent XSS, then apply markdown formatting
    let escaped = escapeHtml(cleanedText);

    // Convert markdown-like formatting to HTML (now safe since content is escaped)
    let html = escaped
      // Headers (escaped content, so &gt; etc won't interfere)
      .replace(/^### (.+)$/gm, '<h4>$1</h4>')
      .replace(/^## (.+)$/gm, '<h3>$1</h3>')
      .replace(/^# (.+)$/gm, '<h2>$1</h2>')
      // Bold
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      // Italic (but not inside URLs which have been escaped)
      .replace(/\*([^*]+)\*/g, '<em>$1</em>')
      // Code blocks
      .replace(/```(\w+)?\n([\s\S]+?)```/g, '<pre><code>$2</code></pre>')
      // Inline code
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      // Lists
      .replace(/^- (.+)$/gm, '<li>$1</li>')
      .replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>')
      // Numbered lists
      .replace(/^\d+\. (.+)$/gm, '<li>$1</li>')
      // Paragraphs
      .replace(/\n\n/g, '</p><p>')
      // Line breaks
      .replace(/\n/g, '<br>');

    html = '<p>' + html + '</p>';

    elements.analysisContent.innerHTML = html;
  }

  /**
   * Escape HTML special characters
   */
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  /**
   * Display enrichment results
   */
  function displayResults(result) {
    showState('results');

    elements.resultType.textContent = result.parsed?.type || 'JA4';
    elements.resultTimestamp.textContent = formatTimestamp(result.timestamp);
    elements.resultHash.textContent = result.hash;

    // Render summary at the top with assessment badge
    renderSummary(result.summary, result.assessment);

    // Render JA4 Database results
    renderJA4DBResults(result.ja4dbResult);

    // Render other sections
    renderKnownMatch(result.knownMatch);
    renderComponents(result.parsed);
    renderAnalysis(result.analysis);
    renderMCPContext(result.mcpContext);

    if (result.model) {
      elements.modelInfo.textContent = `Model: ${result.model}`;
    }

    if (result.usage) {
      elements.usageInfo.textContent = `Tokens: ${result.usage.input_tokens} in / ${result.usage.output_tokens} out`;
    }
  }

  /**
   * Display error
   */
  function displayError(message) {
    showState('error');
    elements.errorText.textContent = message;
  }

  /**
   * Start enrichment process
   */
  async function startEnrichment(hash) {
    // Prevent double-processing
    if (isEnriching && currentHash === hash) {
      return;
    }

    isEnriching = true;
    currentHash = hash;
    showState('loading');
    elements.loadingHash.textContent = hash;

    // Reset loading steps
    updateLoadingStep('parse', 'active');
    updateLoadingStep('ja4db', '');
    updateLoadingStep('analyze', '');

    try {
      // Update steps as we progress (simulated since actual work happens in background)
      setTimeout(() => updateLoadingStep('parse', 'complete'), 200);
      setTimeout(() => {
        updateLoadingStep('ja4db', 'active');
      }, 300);
      setTimeout(() => {
        updateLoadingStep('ja4db', 'complete');
        updateLoadingStep('analyze', 'active');
      }, 1500);

      const result = await browser.runtime.sendMessage({
        type: 'enrich-hash',
        hash: hash
      });

      if (result.success) {
        displayResults(result);
      } else {
        displayError(result.error || 'Unknown error occurred');
      }
    } catch (error) {
      displayError(error.message || 'Failed to communicate with background script');
    } finally {
      isEnriching = false;
    }

    // Refresh history
    loadHistory();
  }

  /**
   * Load and display history
   */
  async function loadHistory() {
    try {
      const response = await browser.runtime.sendMessage({ type: 'get-history' });
      const history = response.history || [];

      if (history.length === 0) {
        elements.historyList.innerHTML = '<p class="empty-history">No recent lookups</p>';
        return;
      }

      let html = '';
      history.forEach((entry, index) => {
        const ja4dbBadge = entry.ja4dbFound
          ? '<span class="history-ja4db" title="Found in JA4DB">📗</span>'
          : '';

        html += `
          <div class="history-item" data-hash="${escapeHtml(entry.hash)}">
            <div class="history-item-header">
              <span class="history-type">${escapeHtml(entry.type)}</span>
              ${ja4dbBadge}
              <span class="history-time">${formatTimestamp(entry.timestamp)}</span>
            </div>
            <code class="history-hash">${escapeHtml(entry.hash)}</code>
            ${entry.knownMatch ? `<span class="history-match">${escapeHtml(entry.knownMatch)}</span>` : ''}
            ${entry.summary ? `<p class="history-summary">${escapeHtml(entry.summary.substring(0, 100))}...</p>` : ''}
          </div>
        `;
      });

      elements.historyList.innerHTML = html;

      // Add click handlers
      elements.historyList.querySelectorAll('.history-item').forEach(item => {
        item.addEventListener('click', () => {
          const hash = item.dataset.hash;
          startEnrichment(hash);
        });
      });
    } catch (error) {
      console.error('Failed to load history:', error);
    }
  }

  /**
   * Clear history
   */
  async function clearHistory() {
    try {
      await browser.runtime.sendMessage({ type: 'clear-history' });
      loadHistory();
    } catch (error) {
      console.error('Failed to clear history:', error);
    }
  }

  /**
   * Toggle history visibility
   */
  function toggleHistory() {
    historyExpanded = !historyExpanded;
    elements.historyContent.classList.toggle('hidden', !historyExpanded);
    elements.historyIcon.textContent = historyExpanded ? '▲' : '▼';

    if (historyExpanded) {
      loadHistory();
    }
  }

  /**
   * Copy hash to clipboard
   */
  async function copyHashToClipboard() {
    if (!currentHash) return;

    try {
      await navigator.clipboard.writeText(currentHash);
      elements.copyHash.textContent = '✓';
      setTimeout(() => {
        elements.copyHash.textContent = '📋';
      }, 1500);
    } catch (error) {
      console.error('Failed to copy:', error);
    }
  }

  /**
   * Open settings page
   */
  function openSettings() {
    browser.runtime.openOptionsPage();
  }

  // Event listeners
  elements.retryBtn?.addEventListener('click', () => {
    if (currentHash) {
      startEnrichment(currentHash);
    }
  });

  elements.copyHash?.addEventListener('click', copyHashToClipboard);
  elements.historyToggle?.addEventListener('click', toggleHistory);
  elements.clearHistory?.addEventListener('click', clearHistory);
  elements.settingsBtn?.addEventListener('click', openSettings);

  // Listen for messages from background script
  browser.runtime.onMessage.addListener((message) => {
    if (message.type === 'enrich-hash') {
      startEnrichment(message.hash);
    } else if (message.type === 'enrichment-error') {
      displayError(message.error);
    }
  });

  /**
   * Check for pending enrichment request on load
   */
  async function checkPendingEnrichment() {
    try {
      const result = await browser.storage.local.get('pendingEnrichment');
      const pending = result.pendingEnrichment;

      if (!pending) return;

      // Only process if it's recent (within last 5 seconds)
      if (Date.now() - pending.timestamp > 5000) {
        await browser.storage.local.remove('pendingEnrichment');
        return;
      }

      // Clear the pending request
      await browser.storage.local.remove('pendingEnrichment');

      // Handle error case
      if (pending.error) {
        displayError(pending.error);
        return;
      }

      // Start enrichment
      if (pending.hash) {
        startEnrichment(pending.hash);
      }
    } catch (error) {
      console.error('Failed to check pending enrichment:', error);
    }
  }

  // Initialize
  loadHistory();
  checkPendingEnrichment();
  console.log('JAH Sidebar loaded');
})();
