/**
 * JAH Options Page Script
 * Handles settings management and API configuration
 */

(function() {
  'use strict';

  // UI Elements
  const elements = {
    apiKey: document.getElementById('api-key'),
    toggleKey: document.getElementById('toggle-key'),
    modelSelect: document.getElementById('model-select'),
    testConnection: document.getElementById('test-connection'),
    connectionStatus: document.getElementById('connection-status'),
    // Integration fields
    braveApiKey: document.getElementById('brave-api-key'),
    braveStatus: document.getElementById('brave-status'),
    vtApiKey: document.getElementById('vt-api-key'),
    vtStatus: document.getElementById('vt-status'),
    shodanApiKey: document.getElementById('shodan-api-key'),
    shodanStatus: document.getElementById('shodan-status'),
    otxApiKey: document.getElementById('otx-api-key'),
    otxStatus: document.getElementById('otx-status'),
    // Data management
    historyCount: document.getElementById('history-count'),
    clearHistory: document.getElementById('clear-history'),
    exportData: document.getElementById('export-data'),
    importData: document.getElementById('import-data'),
    importFile: document.getElementById('import-file'),
    saveSettings: document.getElementById('save-settings'),
    saveStatus: document.getElementById('save-status')
  };

  let apiKeyVisible = false;

  /**
   * Load current settings
   */
  async function loadSettings() {
    try {
      const result = await browser.storage.local.get([
        'claudeApiKey',
        'claudeModel',
        'mcpConfig',
        'enrichmentHistory'
      ]);

      // Claude API settings
      if (result.claudeApiKey) {
        elements.apiKey.value = result.claudeApiKey;
      }

      if (result.claudeModel) {
        elements.modelSelect.value = result.claudeModel;
      }

      // MCP/Integration settings
      if (result.mcpConfig) {
        const config = result.mcpConfig;

        if (config.braveSearch?.apiKey) {
          elements.braveApiKey.value = config.braveSearch.apiKey;
          updateIntegrationStatus('brave', true);
        }

        if (config.threatIntel?.virusTotalApiKey) {
          elements.vtApiKey.value = config.threatIntel.virusTotalApiKey;
          updateIntegrationStatus('vt', true);
        }

        if (config.threatIntel?.shodanApiKey) {
          elements.shodanApiKey.value = config.threatIntel.shodanApiKey;
          updateIntegrationStatus('shodan', true);
        }

        if (config.threatIntel?.otxApiKey) {
          elements.otxApiKey.value = config.threatIntel.otxApiKey;
          updateIntegrationStatus('otx', true);
        }
      }

      // History count
      const historyLength = result.enrichmentHistory?.length || 0;
      elements.historyCount.textContent = `${historyLength} lookup${historyLength !== 1 ? 's' : ''} stored`;

    } catch (error) {
      console.error('Failed to load settings:', error);
      showStatus('Failed to load settings', 'error');
    }
  }

  /**
   * Update integration status badge
   */
  function updateIntegrationStatus(integration, configured) {
    const statusEl = elements[`${integration}Status`];
    if (!statusEl) return;

    if (configured) {
      statusEl.textContent = 'Configured';
      statusEl.className = 'integration-status status-configured';
    } else {
      statusEl.textContent = 'Not configured';
      statusEl.className = 'integration-status';
    }
  }

  /**
   * Save settings
   */
  async function saveSettings() {
    try {
      const apiKey = elements.apiKey.value.trim();
      const model = elements.modelSelect.value;

      // Save Claude settings
      await browser.storage.local.set({
        claudeApiKey: apiKey,
        claudeModel: model
      });

      // Save MCP/Integration settings
      const mcpConfig = {
        braveSearch: {
          apiKey: elements.braveApiKey.value.trim() || null,
          enabled: !!elements.braveApiKey.value.trim()
        },
        webFetch: {
          enabled: true,
          timeout: 10000
        },
        threatIntel: {
          virusTotalApiKey: elements.vtApiKey.value.trim() || null,
          shodanApiKey: elements.shodanApiKey.value.trim() || null,
          otxApiKey: elements.otxApiKey.value.trim() || null,
          enabled: !!(elements.vtApiKey.value.trim() || elements.shodanApiKey.value.trim() || elements.otxApiKey.value.trim())
        }
      };

      await browser.storage.local.set({ mcpConfig });

      // Update status badges
      updateIntegrationStatus('brave', !!elements.braveApiKey.value.trim());
      updateIntegrationStatus('vt', !!elements.vtApiKey.value.trim());
      updateIntegrationStatus('shodan', !!elements.shodanApiKey.value.trim());
      updateIntegrationStatus('otx', !!elements.otxApiKey.value.trim());

      showStatus('Settings saved successfully', 'success');

    } catch (error) {
      console.error('Failed to save settings:', error);
      showStatus('Failed to save settings', 'error');
    }
  }

  /**
   * Toggle API key visibility
   */
  function toggleApiKeyVisibility() {
    apiKeyVisible = !apiKeyVisible;
    elements.apiKey.type = apiKeyVisible ? 'text' : 'password';
    elements.toggleKey.textContent = apiKeyVisible ? '🙈' : '👁';
  }

  /**
   * Toggle visibility for any password field
   */
  function toggleFieldVisibility(targetId) {
    const input = document.getElementById(targetId);
    if (!input) return;

    const button = document.querySelector(`[data-target="${targetId}"]`);
    const isVisible = input.type === 'text';

    input.type = isVisible ? 'password' : 'text';
    if (button) {
      button.textContent = isVisible ? '👁' : '🙈';
    }
  }

  /**
   * Test API connection
   */
  async function testConnection() {
    const apiKey = elements.apiKey.value.trim();

    if (!apiKey) {
      showConnectionStatus('No API key entered', 'error');
      return;
    }

    showConnectionStatus('Testing...', 'pending');
    elements.testConnection.disabled = true;

    try {
      // Save the key first so the API client can use it
      await browser.storage.local.set({ claudeApiKey: apiKey });

      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
          'anthropic-dangerous-direct-browser-access': 'true'
        },
        body: JSON.stringify({
          model: 'claude-sonnet-4-20250514',
          max_tokens: 10,
          messages: [{ role: 'user', content: 'Hi' }]
        })
      });

      if (response.ok) {
        showConnectionStatus('Connection successful!', 'success');
      } else {
        const errorData = await response.json().catch(() => ({}));
        const errorMessage = errorData.error?.message || `HTTP ${response.status}`;
        showConnectionStatus(`Error: ${errorMessage}`, 'error');
      }

    } catch (error) {
      showConnectionStatus(`Error: ${error.message}`, 'error');
    } finally {
      elements.testConnection.disabled = false;
    }
  }

  /**
   * Show connection status
   */
  function showConnectionStatus(message, type) {
    elements.connectionStatus.textContent = message;
    elements.connectionStatus.className = `status-badge status-${type}`;
    elements.connectionStatus.classList.remove('hidden');

    if (type !== 'pending') {
      setTimeout(() => {
        elements.connectionStatus.classList.add('hidden');
      }, 5000);
    }
  }

  /**
   * Show save status message
   */
  function showStatus(message, type) {
    elements.saveStatus.textContent = message;
    elements.saveStatus.className = `status-message status-${type}`;
    elements.saveStatus.classList.remove('hidden');

    setTimeout(() => {
      elements.saveStatus.classList.add('hidden');
    }, 3000);
  }

  /**
   * Clear enrichment history
   */
  async function clearHistory() {
    if (!confirm('Are you sure you want to clear all enrichment history?')) {
      return;
    }

    try {
      await browser.storage.local.set({ enrichmentHistory: [] });
      elements.historyCount.textContent = '0 lookups stored';
      showStatus('History cleared', 'success');
    } catch (error) {
      console.error('Failed to clear history:', error);
      showStatus('Failed to clear history', 'error');
    }
  }

  /**
   * Export all data
   * Prompts user about including sensitive API keys
   */
  async function exportData() {
    try {
      const includeSensitive = confirm(
        'Include API keys in export?\n\n' +
        'Click OK to include API keys (useful for full backup).\n' +
        'Click Cancel to exclude API keys (safer for sharing).'
      );

      const data = await browser.storage.local.get(null);

      // Create export data, optionally redacting sensitive keys
      const exportData = {
        ...data,
        exportDate: new Date().toISOString(),
        version: '1.0.0'
      };

      // Remove sensitive data if user chose not to include it
      if (!includeSensitive) {
        delete exportData.claudeApiKey;
        if (exportData.mcpConfig) {
          exportData.mcpConfig = {
            ...exportData.mcpConfig,
            braveSearch: exportData.mcpConfig.braveSearch ? {
              ...exportData.mcpConfig.braveSearch,
              apiKey: null
            } : null,
            threatIntel: exportData.mcpConfig.threatIntel ? {
              ...exportData.mcpConfig.threatIntel,
              virusTotalApiKey: null,
              shodanApiKey: null,
              otxApiKey: null
            } : null
          };
        }
        exportData._keysRedacted = true;
      }

      const blob = new Blob([JSON.stringify(exportData, null, 2)], {
        type: 'application/json'
      });

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `jah-backup-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      const statusMsg = includeSensitive
        ? 'Data exported (includes API keys)'
        : 'Data exported (API keys excluded)';
      showStatus(statusMsg, 'success');

    } catch (error) {
      console.error('Failed to export data:', error);
      showStatus('Failed to export data', 'error');
    }
  }

  /**
   * Import data from file
   */
  function importData() {
    elements.importFile.click();
  }

  /**
   * Handle file import
   */
  async function handleFileImport(event) {
    const file = event.target.files[0];
    if (!file) return;

    try {
      const text = await file.text();
      const data = JSON.parse(text);

      // Validate it's a JAH backup
      if (!data.version && !data.claudeApiKey && !data.enrichmentHistory) {
        throw new Error('Invalid backup file');
      }

      // Remove metadata before importing
      const { exportDate, version, ...importData } = data;

      if (!confirm('This will overwrite your current settings. Continue?')) {
        return;
      }

      await browser.storage.local.set(importData);

      // Reload settings
      loadSettings();
      showStatus('Data imported successfully', 'success');

    } catch (error) {
      console.error('Failed to import data:', error);
      showStatus('Failed to import data: Invalid file', 'error');
    }

    // Reset file input
    elements.importFile.value = '';
  }

  // Event listeners
  elements.toggleKey?.addEventListener('click', toggleApiKeyVisibility);
  elements.testConnection?.addEventListener('click', testConnection);
  elements.clearHistory?.addEventListener('click', clearHistory);
  elements.exportData?.addEventListener('click', exportData);
  elements.importData?.addEventListener('click', importData);
  elements.importFile?.addEventListener('change', handleFileImport);
  elements.saveSettings?.addEventListener('click', saveSettings);

  // Toggle visibility buttons for integration fields
  document.querySelectorAll('.toggle-visibility').forEach(button => {
    button.addEventListener('click', () => {
      const targetId = button.dataset.target;
      toggleFieldVisibility(targetId);
    });
  });

  // Save on Enter in API key field
  elements.apiKey?.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      saveSettings();
    }
  });

  // Initialize
  loadSettings();

  console.log('JAH Options page loaded');
})();
