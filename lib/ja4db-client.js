/**
 * JA4 Database Client
 * Queries the FoxIO JA4 Database at ja4db.com
 */

const JA4DBClient = {
  API_ENDPOINT: 'https://ja4db.com/api/read/',

  /**
   * Map fingerprint type to API field name
   */
  typeToField: {
    'JA4': 'ja4_fingerprint',
    'JA4S': 'ja4s_fingerprint',
    'JA4H': 'ja4h_fingerprint',
    'JA4X': 'ja4x_fingerprint',
    'JA4T': 'ja4t_fingerprint',
    'JA4TS': 'ja4ts_fingerprint',
    'JA4SSH': 'ja4ssh_fingerprint'
  },

  /**
   * Query the JA4 database for a fingerprint
   * @param {string} hash - The fingerprint hash to look up
   * @param {string} type - The fingerprint type (JA4, JA4S, etc.)
   * @returns {Promise<object>} - Database results
   */
  async lookup(hash, type) {
    const fieldName = this.typeToField[type] || 'ja4_fingerprint';
    const url = `${this.API_ENDPOINT}?${fieldName}=${encodeURIComponent(hash)}`;

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Accept': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error(`JA4DB API returned ${response.status}`);
      }

      const data = await response.json();

      if (!Array.isArray(data) || data.length === 0) {
        return {
          found: false,
          hash,
          type,
          matches: []
        };
      }

      // Process and deduplicate results
      const processed = this.processResults(data);

      return {
        found: true,
        hash,
        type,
        matchCount: data.length,
        matches: processed.matches,
        summary: processed.summary
      };

    } catch (error) {
      console.error('JA4DB lookup error:', error);
      return {
        found: false,
        hash,
        type,
        error: error.message,
        matches: []
      };
    }
  },

  /**
   * Process and summarize database results
   */
  processResults(data) {
    const applications = new Set();
    const libraries = new Set();
    const devices = new Set();
    const operatingSystems = new Set();
    const userAgents = new Set();
    const certificates = new Set();

    let totalObservations = 0;
    let verifiedCount = 0;

    const matches = [];

    for (const record of data) {
      if (record.application) applications.add(record.application);
      if (record.library) libraries.add(record.library);
      if (record.device) devices.add(record.device);
      if (record.os) operatingSystems.add(record.os);
      if (record.user_agent_string) userAgents.add(record.user_agent_string);
      if (record.certificate_authority) certificates.add(record.certificate_authority);

      totalObservations += record.observation_count || 0;
      if (record.verified) verifiedCount++;

      // Create a match entry
      matches.push({
        application: record.application,
        library: record.library,
        device: record.device,
        os: record.os,
        userAgent: record.user_agent_string,
        certificateAuthority: record.certificate_authority,
        observationCount: record.observation_count,
        verified: record.verified,
        notes: record.notes,
        fingerprintString: record.ja4_fingerprint_string || null,
        relatedFingerprints: {
          ja4: record.ja4_fingerprint,
          ja4s: record.ja4s_fingerprint,
          ja4h: record.ja4h_fingerprint,
          ja4x: record.ja4x_fingerprint,
          ja4t: record.ja4t_fingerprint,
          ja4ts: record.ja4ts_fingerprint
        }
      });
    }

    return {
      matches,
      summary: {
        applications: Array.from(applications),
        libraries: Array.from(libraries),
        devices: Array.from(devices),
        operatingSystems: Array.from(operatingSystems),
        userAgents: Array.from(userAgents).slice(0, 5), // Limit to 5 user agents
        certificates: Array.from(certificates),
        totalObservations,
        verifiedCount,
        totalRecords: data.length
      }
    };
  },

  /**
   * Get a human-readable summary of database results
   */
  formatSummary(dbResult) {
    if (!dbResult.found) {
      return 'This fingerprint was not found in the JA4 database.';
    }

    const { summary } = dbResult;
    const parts = [];

    if (summary.applications.length > 0) {
      parts.push(`Associated with: ${summary.applications.join(', ')}`);
    }

    if (summary.libraries.length > 0) {
      parts.push(`Libraries: ${summary.libraries.join(', ')}`);
    }

    if (summary.operatingSystems.length > 0) {
      parts.push(`Operating Systems: ${summary.operatingSystems.join(', ')}`);
    }

    if (summary.devices.length > 0) {
      parts.push(`Devices: ${summary.devices.join(', ')}`);
    }

    parts.push(`${summary.totalRecords} database record(s), ${summary.verifiedCount} verified`);
    parts.push(`${summary.totalObservations} total observations`);

    return parts.join('\n');
  },

  /**
   * Check if database is accessible
   */
  async checkAvailability() {
    try {
      const response = await fetch(`${this.API_ENDPOINT}?limit=1`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      });
      return response.ok;
    } catch {
      return false;
    }
  }
};

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = JA4DBClient;
}
