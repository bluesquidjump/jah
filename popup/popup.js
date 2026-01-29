/**
 * JAH Popup Script
 * Handles toolbar button popup actions
 */

(function() {
  'use strict';

  // DOM elements
  const openSidebarBtn = document.getElementById('open-sidebar');
  const openSettingsBtn = document.getElementById('open-settings');
  const apiStatus = document.getElementById('api-status');

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

  // Event listeners
  openSidebarBtn.addEventListener('click', openSidebar);
  openSettingsBtn.addEventListener('click', openSettings);

  // Initialize
  checkApiStatus();
})();
