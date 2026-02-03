/**
 * MCP (Model Context Protocol) Client
 * Provides integrations with external services for enhanced enrichment
 *
 * Current integrations:
 * - Brave Search: Search for fingerprint information online
 * - Web Fetch: Fetch from external fingerprint databases
 * - Threat Intel: Connect to threat intelligence platforms (future)
 */

const MCPClient = {
  /**
   * Configuration for MCP integrations
   */
  defaultConfig: {
    braveSearch: {
      enabled: false,
      apiKey: null
    },
    webFetch: {
      enabled: true, // Enabled by default - no API key needed
      timeout: 10000
    },
    threatIntel: {
      enabled: false,
      virusTotalApiKey: null,
      shodanApiKey: null
    }
  },

  /**
   * Known fingerprint database URLs for web fetch
   */
  fingerprintDatabases: [
    {
      name: 'SSL Blacklist',
      url: 'https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv',
      type: 'ja3', // JA3 can help correlate with JA4
      format: 'csv'
    },
    {
      name: 'TLS Fingerprint',
      url: 'https://tlsfingerprint.io/api/lookup',
      type: 'tls',
      format: 'json'
    }
  ],

  /**
   * Get MCP configuration from storage
   */
  async getConfig() {
    const result = await browser.storage.local.get('mcpConfig');
    return { ...this.defaultConfig, ...result.mcpConfig };
  },

  /**
   * Save MCP configuration to storage
   */
  async setConfig(config) {
    await browser.storage.local.set({ mcpConfig: config });
  },

  /**
   * Check if any MCP integration is available
   */
  async isAvailable() {
    const config = await this.getConfig();
    return config.braveSearch?.enabled ||
           config.webFetch?.enabled ||
           config.threatIntel?.enabled;
  },

  /**
   * Fetch additional context from all enabled sources
   * @param {string} hash - The JA4 fingerprint hash
   * @param {string} type - The fingerprint type
   * @returns {Promise<object>} - Combined context from all sources
   */
  async fetchContext(hash, type) {
    const config = await this.getConfig();
    const context = {
      sources: [],
      data: {},
      errors: []
    };

    const promises = [];

    // Brave Search
    if (config.braveSearch?.enabled && config.braveSearch?.apiKey) {
      promises.push(
        this.searchBrave(hash, type, config.braveSearch.apiKey)
          .then(result => {
            if (result) {
              context.sources.push('braveSearch');
              context.data.braveSearch = result;
            }
          })
          .catch(error => {
            context.errors.push({ source: 'braveSearch', error: error.message });
          })
      );
    }

    // Web Fetch - external databases
    if (config.webFetch?.enabled) {
      promises.push(
        this.fetchExternalDatabases(hash, type, config.webFetch.timeout)
          .then(result => {
            if (result && result.length > 0) {
              context.sources.push('webFetch');
              context.data.webFetch = result;
            }
          })
          .catch(error => {
            context.errors.push({ source: 'webFetch', error: error.message });
          })
      );
    }

    // Threat Intel
    if (config.threatIntel?.enabled) {
      promises.push(
        this.queryThreatIntel(hash, type, config.threatIntel)
          .then(result => {
            if (result) {
              context.sources.push('threatIntel');
              context.data.threatIntel = result;
            }
          })
          .catch(error => {
            context.errors.push({ source: 'threatIntel', error: error.message });
          })
      );
    }

    await Promise.all(promises);
    return context;
  },

  /**
   * Search Brave for fingerprint information
   * @param {string} hash - The fingerprint hash
   * @param {string} type - The fingerprint type
   * @param {string} apiKey - Brave Search API key
   */
  async searchBrave(hash, type, apiKey) {
    const query = `"${hash}" ${type} fingerprint`;

    try {
      const response = await fetch(
        `https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(query)}&count=5`,
        {
          headers: {
            'Accept': 'application/json',
            'X-Subscription-Token': apiKey
          }
        }
      );

      if (!response.ok) {
        throw new Error(`Brave Search API returned ${response.status}`);
      }

      const data = await response.json();

      if (!data.web?.results || data.web.results.length === 0) {
        return null;
      }

      return {
        query,
        results: data.web.results.map(r => ({
          title: r.title,
          url: r.url,
          description: r.description,
          age: r.age
        }))
      };
    } catch (error) {
      console.error('Brave Search error:', error);
      throw error;
    }
  },

  /**
   * Fetch from external fingerprint databases
   * @param {string} hash - The fingerprint hash
   * @param {string} type - The fingerprint type
   * @param {number} timeout - Request timeout in ms
   */
  async fetchExternalDatabases(hash, type, timeout = 10000) {
    const results = [];

    // Try to correlate with threat intel feeds
    // Note: Most require the full fingerprint string, not just the hash

    // Check SSL Blacklist for malicious associations
    try {
      const sslblResult = await this.checkSSLBlacklist(hash, timeout);
      if (sslblResult) {
        results.push({
          source: 'SSL Blacklist (abuse.ch)',
          ...sslblResult
        });
      }
    } catch (error) {
      console.warn('SSL Blacklist check failed:', error.message);
    }

    return results;
  },

  /**
   * Check SSL Blacklist for the fingerprint
   * Note: This primarily uses JA3, but can help correlate threat intel
   */
  async checkSSLBlacklist(hash, timeout) {
    // The SSL Blacklist primarily uses JA3 fingerprints
    // For JA4, we check if the hash appears in any threat reports

    // This is a placeholder - in production, you would:
    // 1. Download and cache the CSV blacklist
    // 2. Check if the fingerprint or related hashes appear
    // 3. Return any threat associations

    return null;
  },

  /**
   * Query threat intelligence platforms
   * @param {string} hash - The fingerprint hash
   * @param {string} type - The fingerprint type
   * @param {object} config - Threat intel configuration
   */
  async queryThreatIntel(hash, type, config) {
    const results = {};

    // VirusTotal integration
    if (config.virusTotalApiKey) {
      try {
        const vtResult = await this.queryVirusTotal(hash, config.virusTotalApiKey);
        if (vtResult) {
          results.virusTotal = vtResult;
        }
      } catch (error) {
        console.warn('VirusTotal query failed:', error.message);
      }
    }

    // Shodan integration
    if (config.shodanApiKey) {
      try {
        const shodanResult = await this.queryShodan(hash, config.shodanApiKey);
        if (shodanResult) {
          results.shodan = shodanResult;
        }
      } catch (error) {
        console.warn('Shodan query failed:', error.message);
      }
    }

    return Object.keys(results).length > 0 ? results : null;
  },

  /**
   * Query VirusTotal for fingerprint associations
   * Note: VT uses JA3 primarily, but behavior data can help
   */
  async queryVirusTotal(hash, apiKey) {
    // VirusTotal API v3 endpoint for searching
    // The fingerprint might appear in behavior reports

    try {
      const response = await fetch(
        `https://www.virustotal.com/api/v3/search?query=${encodeURIComponent('"' + hash + '"')}`,
        {
          headers: {
            'x-apikey': apiKey
          }
        }
      );

      if (!response.ok) {
        if (response.status === 401) {
          throw new Error('Invalid VirusTotal API key');
        }
        return null;
      }

      const data = await response.json();

      if (!data.data || data.data.length === 0) {
        return null;
      }

      return {
        matchCount: data.data.length,
        samples: data.data.slice(0, 5).map(item => ({
          id: item.id,
          type: item.type,
          attributes: {
            meaningfulName: item.attributes?.meaningful_name,
            lastAnalysisStats: item.attributes?.last_analysis_stats
          }
        }))
      };
    } catch (error) {
      console.error('VirusTotal query error:', error);
      throw error;
    }
  },

  /**
   * Query Shodan for fingerprint data
   */
  async queryShodan(hash, apiKey) {
    // Shodan can search for SSL/TLS fingerprints
    // JA3 is supported, JA4 support may vary

    try {
      const response = await fetch(
        `https://api.shodan.io/shodan/host/search?key=${encodeURIComponent(apiKey)}&query=${encodeURIComponent('ssl.ja3:"' + hash + '"')}`,
        {
          headers: {
            'Accept': 'application/json'
          }
        }
      );

      if (!response.ok) {
        if (response.status === 401) {
          throw new Error('Invalid Shodan API key');
        }
        return null;
      }

      const data = await response.json();

      if (!data.matches || data.matches.length === 0) {
        return null;
      }

      return {
        total: data.total,
        matches: data.matches.slice(0, 5).map(m => ({
          ip: m.ip_str,
          port: m.port,
          org: m.org,
          location: m.location,
          product: m.product
        }))
      };
    } catch (error) {
      console.error('Shodan query error:', error);
      throw error;
    }
  },

  /**
   * Register/configure a specific integration
   */
  async configureIntegration(name, settings) {
    const config = await this.getConfig();

    if (name === 'braveSearch') {
      config.braveSearch = {
        ...config.braveSearch,
        ...settings,
        enabled: !!settings.apiKey
      };
    } else if (name === 'threatIntel') {
      config.threatIntel = {
        ...config.threatIntel,
        ...settings,
        enabled: !!(settings.virusTotalApiKey || settings.shodanApiKey)
      };
    } else if (name === 'webFetch') {
      config.webFetch = {
        ...config.webFetch,
        ...settings
      };
    }

    await this.setConfig(config);
  },

  /**
   * Disable a specific integration
   */
  async disableIntegration(name) {
    const config = await this.getConfig();

    if (config[name]) {
      config[name].enabled = false;
    }

    await this.setConfig(config);
  },

  /**
   * Get status of all integrations
   */
  async getStatus() {
    const config = await this.getConfig();

    return {
      braveSearch: {
        enabled: config.braveSearch?.enabled || false,
        configured: !!config.braveSearch?.apiKey
      },
      webFetch: {
        enabled: config.webFetch?.enabled || false,
        configured: true // No API key needed
      },
      threatIntel: {
        enabled: config.threatIntel?.enabled || false,
        virusTotal: !!config.threatIntel?.virusTotalApiKey,
        shodan: !!config.threatIntel?.shodanApiKey
      }
    };
  }
};

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = MCPClient;
}
