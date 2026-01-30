/**
 * Claude API Integration for JA4 Hash Enrichment
 */

const ClaudeAPI = {
  API_ENDPOINT: 'https://api.anthropic.com/v1/messages',

  /**
   * System prompt for JA4 fingerprint analysis
   */
  SYSTEM_PROMPT: `You are an expert network security analyst specializing in TLS/SSL fingerprinting and network traffic analysis. Your task is to analyze JA4 fingerprint hashes and provide detailed, actionable intelligence.

IMPORTANT: Your response MUST begin with a "Summary" section containing a 3-5 sentence narrative overview that a security analyst can quickly read to understand the key findings. This summary should be written in plain English and highlight the most important aspects: what this fingerprint likely represents, whether it's benign or suspicious, and any immediate actionable insights.

After the summary, provide detailed analysis:

1. **Fingerprint Type & Components**: Identify the JA4 variant and explain each component:
   - For JA4: protocol (TCP/QUIC), TLS version, SNI type, cipher count, extension count, ALPN
   - For JA4S: chosen cipher suite, server extensions
   - For JA4H: HTTP method, version, headers, cookies
   - For JA4SSH: packet patterns indicating interactive vs automated sessions
   - For JA4T/JA4TS: TCP options, window size, MSS

2. **Behavioral Analysis**: Based on the fingerprint components and any database matches, identify what type of client/application produces this fingerprint:
   - Common browsers (Chrome, Firefox, Safari, Edge)
   - Programming libraries (curl, requests, wget, Go net/http, Node.js)
   - Bots and crawlers (Googlebot, security scanners)
   - Potentially malicious tools
   - Mobile applications
   - IoT devices

3. **Security Assessment**: Evaluate security implications:
   - TLS version concerns (outdated versions)
   - Cipher suite strength
   - Missing security extensions
   - Indicators of automated/malicious activity
   - Known threat associations

4. **Confidence Level**: Rate your overall confidence (High/Medium/Low) with explanation.

Format your response with clear markdown headers. Be concise but thorough.

IMPORTANT: At the very end of your response, you MUST include a structured assessment line in exactly this format:
ASSESSMENT: [category] | [threat_level] | [confidence]

Where:
- category is exactly one of: browser, vpn, malware, tool, library, bot, suspicious, benign
- threat_level is exactly one of: critical, high, medium, low, none
- confidence is exactly one of: high, medium, low

Examples:
- ASSESSMENT: browser | none | high
- ASSESSMENT: malware | critical | high
- ASSESSMENT: library | low | medium
- ASSESSMENT: suspicious | medium | low

Choose "benign" for legitimate applications like browsers, common libraries, and known safe tools.
Choose "malware" only when there is strong evidence of malicious intent.
Choose "suspicious" when behavior is anomalous but not definitively malicious.`,

  /**
   * Get API key from storage
   */
  async getApiKey() {
    const result = await browser.storage.local.get('claudeApiKey');
    return result.claudeApiKey || null;
  },

  /**
   * Set API key in storage
   */
  async setApiKey(apiKey) {
    await browser.storage.local.set({ claudeApiKey: apiKey });
  },

  /**
   * Get model preference from storage
   */
  async getModel() {
    const result = await browser.storage.local.get('claudeModel');
    return result.claudeModel || 'claude-sonnet-4-20250514';
  },

  /**
   * Set model preference in storage
   */
  async setModel(model) {
    await browser.storage.local.set({ claudeModel: model });
  },

  /**
   * Enrich a JA4 fingerprint hash
   * @param {string} hash - The JA4 fingerprint to analyze
   * @param {object} parsedData - Pre-parsed fingerprint data from JA4Parser
   * @param {object} knownMatch - Any known fingerprint match from local database
   * @param {object} ja4dbResult - Results from JA4 database lookup
   * @returns {Promise<object>} - Enrichment results
   */
  async enrichHash(hash, parsedData = null, knownMatch = null, ja4dbResult = null) {
    const apiKey = await this.getApiKey();
    if (!apiKey) {
      throw new Error('API key not configured. Please set your Claude API key in the extension options.');
    }

    const model = await this.getModel();

    // Build the user message with all available context
    let userMessage = `Analyze this JA4 fingerprint hash and provide your assessment.\n\n`;
    userMessage += `**Hash:** \`${hash}\`\n`;

    if (parsedData) {
      userMessage += `\n**Detected Type:** ${parsedData.type}\n`;
      if (parsedData.components) {
        userMessage += `\n**Parsed Components:**\n\`\`\`json\n${JSON.stringify(parsedData.components, null, 2)}\n\`\`\`\n`;
      }
      if (parsedData.analysis) {
        userMessage += `\n**Initial Analysis:**\n\`\`\`json\n${JSON.stringify(parsedData.analysis, null, 2)}\n\`\`\`\n`;
      }
    }

    // Include JA4 Database results if available
    if (ja4dbResult && ja4dbResult.found) {
      userMessage += `\n**JA4 Database Results (ja4db.com):**\n`;
      userMessage += `- Queried fingerprint type: ${ja4dbResult.type}\n`;
      userMessage += `- Found ${ja4dbResult.matchCount} matching record(s)\n`;

      const summary = ja4dbResult.summary;

      // Show direct applications (associated with the queried fingerprint type)
      if (summary.directApplications && summary.directApplications.length > 0) {
        userMessage += `- Applications (directly identified by this ${ja4dbResult.type} fingerprint): ${summary.directApplications.join(', ')}\n`;
      }

      // Show related applications with clear caveat
      if (summary.relatedApplications && summary.relatedApplications.length > 0) {
        userMessage += `- Related Applications (identified by DIFFERENT fingerprint types in the same record, NOT by the queried ${ja4dbResult.type}): ${summary.relatedApplications.join(', ')}\n`;
        userMessage += `  IMPORTANT: These related applications are associated with a different fingerprint type (likely JA4) in the database record. Do NOT attribute these to the queried ${ja4dbResult.type} fingerprint.\n`;
      }

      // Fallback for older format without direct/related distinction
      if (!summary.directApplications && !summary.relatedApplications && summary.applications && summary.applications.length > 0) {
        userMessage += `- Known Applications: ${summary.applications.join(', ')}\n`;
      }

      if (summary.libraries.length > 0) {
        userMessage += `- Known Libraries: ${summary.libraries.join(', ')}\n`;
      }
      if (summary.operatingSystems.length > 0) {
        userMessage += `- Operating Systems: ${summary.operatingSystems.join(', ')}\n`;
      }
      if (summary.devices.length > 0) {
        userMessage += `- Devices: ${summary.devices.join(', ')}\n`;
      }
      userMessage += `- Verified Records: ${summary.verifiedCount} of ${summary.totalRecords}\n`;
      userMessage += `- Total Observations: ${summary.totalObservations}\n`;

      // Include sample user agents if available
      if (summary.userAgents && summary.userAgents.length > 0) {
        userMessage += `\n**Sample User Agents from Database:**\n`;
        summary.userAgents.slice(0, 3).forEach(ua => {
          userMessage += `- \`${ua}\`\n`;
        });
      }

      // Include fingerprint string if available
      const matchWithString = ja4dbResult.matches.find(m => m.fingerprintString);
      if (matchWithString) {
        userMessage += `\n**Full Fingerprint String:**\n\`${matchWithString.fingerprintString}\`\n`;
      }
    } else if (ja4dbResult) {
      userMessage += `\n**JA4 Database:** No matches found in ja4db.com\n`;
    }

    // Include local database match if available
    if (knownMatch) {
      userMessage += `\n**Local Database Match:**\n- Name: ${knownMatch.name}\n- Category: ${knownMatch.category}\n- Description: ${knownMatch.description || 'N/A'}\n`;
    }

    userMessage += `\nRemember to start with a 3-5 sentence Summary section providing the key takeaways.`;

    try {
      const response = await fetch(this.API_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
          'anthropic-dangerous-direct-browser-access': 'true'
        },
        body: JSON.stringify({
          model: model,
          max_tokens: 2048,
          system: this.SYSTEM_PROMPT,
          messages: [
            {
              role: 'user',
              content: userMessage
            }
          ]
        })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        if (response.status === 401) {
          throw new Error('Invalid API key. Please check your Claude API key in settings.');
        } else if (response.status === 429) {
          throw new Error('Rate limit exceeded. Please try again later.');
        } else if (response.status === 400) {
          throw new Error(`Bad request: ${errorData.error?.message || 'Unknown error'}`);
        }
        throw new Error(`API error (${response.status}): ${errorData.error?.message || 'Unknown error'}`);
      }

      const data = await response.json();

      if (!data.content || !data.content[0]) {
        throw new Error('Invalid response from Claude API');
      }

      const analysisText = data.content[0].text;

      // Extract the summary section
      const summary = this.extractSummary(analysisText);

      // Extract structured assessment
      const assessment = this.extractAssessment(analysisText);

      return {
        success: true,
        summary: summary,
        analysis: analysisText,
        assessment: assessment,
        model: data.model,
        usage: data.usage,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        throw new Error('Network error. Please check your internet connection.');
      }
      throw error;
    }
  },

  /**
   * Extract structured assessment from the analysis
   * Returns { category, threatLevel, confidence } or null
   */
  extractAssessment(analysisText) {
    // Match the ASSESSMENT line at the end of the response
    const pattern = /ASSESSMENT:\s*(\w+)\s*\|\s*(\w+)\s*\|\s*(\w+)\s*$/im;
    const match = analysisText.match(pattern);

    if (!match) {
      return null;
    }

    const validCategories = ['browser', 'vpn', 'malware', 'tool', 'library', 'bot', 'suspicious', 'benign'];
    const validThreatLevels = ['critical', 'high', 'medium', 'low', 'none'];
    const validConfidences = ['high', 'medium', 'low'];

    const category = match[1].toLowerCase();
    const threatLevel = match[2].toLowerCase();
    const confidence = match[3].toLowerCase();

    // Validate extracted values
    if (!validCategories.includes(category) ||
        !validThreatLevels.includes(threatLevel) ||
        !validConfidences.includes(confidence)) {
      console.warn('JAH: Invalid assessment values:', { category, threatLevel, confidence });
      return null;
    }

    return { category, threatLevel, confidence };
  },

  /**
   * Extract the summary section from the analysis
   */
  extractSummary(analysisText) {
    // Try to find a Summary section
    const summaryPatterns = [
      /^##?\s*Summary\s*\n+([\s\S]*?)(?=\n##?\s|\n\*\*[A-Z]|$)/im,
      /^Summary:?\s*\n+([\s\S]*?)(?=\n##?\s|\n\*\*[A-Z]|$)/im,
      /^\*\*Summary\*\*:?\s*\n+([\s\S]*?)(?=\n##?\s|\n\*\*[A-Z]|$)/im
    ];

    for (const pattern of summaryPatterns) {
      const match = analysisText.match(pattern);
      if (match && match[1]) {
        return match[1].trim();
      }
    }

    // If no explicit summary section, take the first paragraph
    const firstParagraph = analysisText.split(/\n\n/)[0];
    if (firstParagraph && firstParagraph.length > 50) {
      return firstParagraph.trim();
    }

    return null;
  },

  /**
   * Test API connection
   */
  async testConnection() {
    const apiKey = await this.getApiKey();
    if (!apiKey) {
      return { success: false, error: 'No API key configured' };
    }

    try {
      const response = await fetch(this.API_ENDPOINT, {
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
        return { success: true };
      } else {
        const errorData = await response.json().catch(() => ({}));
        return {
          success: false,
          error: errorData.error?.message || `HTTP ${response.status}`
        };
      }
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
};

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ClaudeAPI;
}
