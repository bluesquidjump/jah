/**
 * JAH Popup Script
 * Handles toolbar button popup actions and local database status
 */

(function() {
  'use strict';

  // DOM elements
  const openSidebarBtn = document.getElementById('open-sidebar');
  const openSettingsBtn = document.getElementById('open-settings');
  const apiStatus = document.getElementById('api-status');
  const dbRecords = document.getElementById('db-records');
  const dbLastSync = document.getElementById('db-last-sync');
  const syncBtn = document.getElementById('sync-btn');
  const syncProgress = document.getElementById('sync-progress');
  const progressFill = document.getElementById('progress-fill');
  const progressText = document.getElementById('progress-text');

  /**
   * Open the JAH sidebar
   */
  function openSidebar() {
    browser.sidebarAction.open();
    window.close();
  }

  /**
   * Open the extension settings
   */
  function openSettings() {
    browser.runtime.openOptionsPage();
    window.close();
  }

  /**
   * Check API key status
   */
  async function checkApiStatus() {
    try {
      const result = await browser.storage.local.get('claudeApiKey');
      if (result.claudeApiKey) {
        apiStatus.textContent = 'Configured';
        apiStatus.className = 'status-value configured';
      } else {
        apiStatus.textContent = 'Not Set';
        apiStatus.className = 'status-value not-configured';
      }
    } catch (error) {
      apiStatus.textContent = 'Error';
      apiStatus.className = 'status-value not-configured';
    }
  }

  /**
   * Format number with commas
   */
  function formatNumber(num) {
    return num.toLocaleString();
  }

  /**
   * Format relative time
   */
  function formatRelativeTime(dateString) {
    if (!dateString) return 'Never';

    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;

    return date.toLocaleDateString();
  }

  /**
   * Check local database status
   */
  async function checkDbStatus() {
    try {
      const status = await browser.runtime.sendMessage({ type: 'get-local-db-status' });

      if (status.recordCount) {
        dbRecords.textContent = formatNumber(status.recordCount);
      } else {
        dbRecords.textContent = 'Not synced';
      }

      if (status.lastSync) {
        dbLastSync.textContent = formatRelativeTime(status.lastSync);
        dbLastSync.title = new Date(status.lastSync).toLocaleString();
      } else {
        dbLastSync.textContent = 'Never';
      }

      if (status.syncing) {
        showSyncProgress();
      } else {
        hideSyncProgress();
      }

    } catch (error) {
      console.error('Failed to get DB status:', error);
      dbRecords.textContent = 'Error';
      dbLastSync.textContent = 'Unknown';
    }
  }

  /**
   * Show sync progress UI
   */
  function showSyncProgress() {
    syncProgress.style.display = 'block';
    syncBtn.disabled = true;
    syncBtn.classList.add('syncing');
  }

  /**
   * Hide sync progress UI
   */
  function hideSyncProgress() {
    syncProgress.style.display = 'none';
    syncBtn.disabled = false;
    syncBtn.classList.remove('syncing');
  }

  /**
   * Update progress bar
   */
  function updateProgress(progress, message) {
    if (progress >= 0 && progress <= 100) {
      progressFill.style.width = `${progress}%`;
    }
    if (message) {
      progressText.textContent = message;
    }
  }

  /**
   * Start database sync
   */
  async function startSync() {
    showSyncProgress();
    updateProgress(0, 'Starting sync...');

    try {
      const result = await browser.runtime.sendMessage({ type: 'sync-local-db' });

      if (result.success) {
        updateProgress(100, 'Sync complete!');
        setTimeout(() => {
          hideSyncProgress();
          checkDbStatus();
        }, 1500);
      } else {
        updateProgress(0, `Error: ${result.error}`);
        setTimeout(hideSyncProgress, 3000);
      }
    } catch (error) {
      updateProgress(0, `Error: ${error.message}`);
      setTimeout(hideSyncProgress, 3000);
    }
  }

  /**
   * Handle sync progress messages from background
   */
  browser.runtime.onMessage.addListener((message) => {
    if (message.type === 'sync-progress') {
      showSyncProgress();
      updateProgress(message.progress || 0, message.message);
    }
  });

  // Event listeners
  openSidebarBtn.addEventListener('click', openSidebar);
  openSettingsBtn.addEventListener('click', openSettings);
  syncBtn.addEventListener('click', startSync);

  // Initialize
  checkApiStatus();
  checkDbStatus();
})();
