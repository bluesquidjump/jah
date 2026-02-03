/**
 * Threat Intelligence Client for File Hash Enrichment
 * Queries VirusTotal, MalwareBazaar (abuse.ch), and AlienVault OTX
 */

const ThreatIntelClient = {
  /**
   * Query VirusTotal v3 API for file hash information
   * @param {string} hash - File hash (MD5, SHA1, or SHA256)
   * @param {string} apiKey - VirusTotal API key
   * @returns {Promise<object>}
   */
  async queryVirusTotal(hash, apiKey) {
    if (!apiKey) {
      return { found: false, error: 'No VirusTotal API key configured' };
    }

    try {
      const response = await fetch(
        `https://www.virustotal.com/api/v3/files/${encodeURIComponent(hash)}`,
        {
          headers: {
            'x-apikey': apiKey
          }
        }
      );

      if (response.status === 404) {
        return { found: false };
      }

      if (response.status === 429) {
        return { found: false, error: 'VirusTotal rate limit exceeded', rateLimited: true };
      }

      if (response.status === 401) {
        return { found: false, error: 'Invalid VirusTotal API key' };
      }

      if (!response.ok) {
        return { found: false, error: `VirusTotal API error (${response.status})` };
      }

      const data = await response.json();
      const attrs = data.data?.attributes;
      if (!attrs) {
        return { found: false };
      }

      const stats = attrs.last_analysis_stats || {};
      const totalEngines = (stats.malicious || 0) + (stats.undetected || 0) +
                          (stats.suspicious || 0) + (stats.harmless || 0) +
                          (stats.timeout || 0) + (stats.failure || 0) +
                          (stats.confirmed_timeout || 0) + (stats.type_unsupported || 0);

      // Build vendor detections list
      const vendorDetections = [];
      const lastResults = attrs.last_analysis_results || {};
      for (const [vendor, result] of Object.entries(lastResults)) {
        if (result.category === 'malicious' || result.category === 'suspicious') {
          vendorDetections.push({
            vendor,
            result: result.result || result.category,
            category: result.category
          });
        }
      }

      // Sort by category (malicious first) then vendor name
      vendorDetections.sort((a, b) => {
        if (a.category !== b.category) return a.category === 'malicious' ? -1 : 1;
        return a.vendor.localeCompare(b.vendor);
      });

      return {
        found: true,
        detectionStats: stats,
        totalEngines,
        maliciousCount: stats.malicious || 0,
        suspiciousCount: stats.suspicious || 0,
        meaningfulName: attrs.meaningful_name || null,
        fileType: attrs.type_description || attrs.type_tag || null,
        fileSize: attrs.size || null,
        firstSeen: attrs.first_submission_date
          ? new Date(attrs.first_submission_date * 1000).toISOString()
          : null,
        lastSeen: attrs.last_analysis_date
          ? new Date(attrs.last_analysis_date * 1000).toISOString()
          : null,
        tags: attrs.tags || [],
        vendorDetections,
        sha256: attrs.sha256 || null,
        sha1: attrs.sha1 || null,
        md5: attrs.md5 || null
      };
    } catch (error) {
      console.error('ThreatIntel: VirusTotal query error:', error);
      return { found: false, error: error.message };
    }
  },

  /**
   * Query MalwareBazaar (abuse.ch) for file hash information
   * No API key required
   * @param {string} hash - File hash (MD5, SHA1, or SHA256)
   * @returns {Promise<object>}
   */
  async queryMalwareBazaar(hash) {
    try {
      const formData = new URLSearchParams();
      formData.append('query', 'get_info');
      formData.append('hash', hash);

      const response = await fetch('https://mb-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: formData.toString()
      });

      if (!response.ok) {
        return { found: false, error: `MalwareBazaar API error (${response.status})` };
      }

      const data = await response.json();

      if (data.query_status !== 'ok' || !data.data || data.data.length === 0) {
        return { found: false };
      }

      const sample = data.data[0];
      return {
        found: true,
        fileName: sample.file_name || null,
        fileType: sample.file_type_mime || sample.file_type || null,
        signature: sample.signature || null,
        tags: sample.tags || [],
        firstSeen: sample.first_seen || null,
        lastSeen: sample.last_seen || null,
        reporter: sample.reporter || null,
        deliveryMethod: sample.delivery_method || null,
        sha256: sample.sha256_hash || null,
        sha1: sample.sha1_hash || null,
        md5: sample.md5_hash || null
      };
    } catch (error) {
      console.error('ThreatIntel: MalwareBazaar query error:', error);
      return { found: false, error: error.message };
    }
  },

  /**
   * Query AlienVault OTX for file hash information
   * @param {string} hash - File hash (MD5, SHA1, or SHA256)
   * @param {string} apiKey - OTX API key
   * @returns {Promise<object>}
   */
  async queryAlienVaultOTX(hash, apiKey) {
    if (!apiKey) {
      return { found: false, error: 'No OTX API key configured' };
    }

    try {
      const response = await fetch(
        `https://otx.alienvault.com/api/v1/indicators/file/${encodeURIComponent(hash)}/general`,
        {
          headers: {
            'X-OTX-API-KEY': apiKey
          }
        }
      );

      if (response.status === 404) {
        return { found: false };
      }

      if (response.status === 401) {
        return { found: false, error: 'Invalid OTX API key' };
      }

      if (!response.ok) {
        return { found: false, error: `OTX API error (${response.status})` };
      }

      const data = await response.json();

      const pulseCount = data.pulse_info?.count || 0;
      const pulses = data.pulse_info?.pulses || [];

      // Extract malware families from pulse tags
      const malwareFamilies = new Set();
      pulses.forEach(pulse => {
        if (pulse.tags) {
          pulse.tags.forEach(tag => {
            if (tag.toLowerCase() !== 'malware' && tag.toLowerCase() !== 'ioc') {
              malwareFamilies.add(tag);
            }
          });
        }
        if (pulse.malware_families) {
          pulse.malware_families.forEach(f => malwareFamilies.add(f.display_name || f));
        }
      });

      return {
        found: pulseCount > 0,
        pulseCount,
        pulseNames: pulses.slice(0, 5).map(p => p.name),
        malwareFamilies: Array.from(malwareFamilies).slice(0, 10),
        fileType: data.type || null
      };
    } catch (error) {
      console.error('ThreatIntel: AlienVault OTX query error:', error);
      return { found: false, error: error.message };
    }
  },

  /**
   * Query all configured threat intel sources in parallel
   * @param {string} hash - File hash
   * @param {object} config - Configuration with API keys
   * @returns {Promise<object>} - Aggregated results
   */
  async queryAll(hash, config = {}) {
    const results = {
      virusTotal: null,
      malwareBazaar: null,
      alienVaultOTX: null,
      errors: []
    };

    const promises = [];

    // VirusTotal (requires API key)
    if (config.virusTotalApiKey) {
      promises.push(
        this.queryVirusTotal(hash, config.virusTotalApiKey)
          .then(r => { results.virusTotal = r; })
          .catch(e => { results.errors.push({ source: 'VirusTotal', error: e.message }); })
      );
    }

    // MalwareBazaar (no API key required)
    promises.push(
      this.queryMalwareBazaar(hash)
        .then(r => { results.malwareBazaar = r; })
        .catch(e => { results.errors.push({ source: 'MalwareBazaar', error: e.message }); })
    );

    // AlienVault OTX (requires API key)
    if (config.otxApiKey) {
      promises.push(
        this.queryAlienVaultOTX(hash, config.otxApiKey)
          .then(r => { results.alienVaultOTX = r; })
          .catch(e => { results.errors.push({ source: 'AlienVault OTX', error: e.message }); })
      );
    }

    await Promise.allSettled(promises);
    return results;
  }
};

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ThreatIntelClient;
}
