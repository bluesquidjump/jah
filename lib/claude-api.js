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
   * System prompt for file hash analysis
   */
  FILE_HASH_SYSTEM_PROMPT: `You are an expert malware analyst specializing in file hash threat intelligence analysis. Your task is to analyze file hashes and their associated threat intelligence data to provide clear, actionable assessments.

CRITICAL SAFETY RULES:
- NEVER suggest downloading, executing, or detonating any files
- NEVER provide download URLs, sandbox submission links, or direct links to malware samples
- NEVER include shell commands that could be used to fetch or run malicious files
- Your analysis must be based ONLY on the provided metadata from threat intelligence services
- Focus on identification, classification, and defensive recommendations only

Your response MUST include:

1. **Summary**: Exactly 3 sentences: (1) what this file is, (2) the threat level, (3) recommended defensive action.

2. **Detection Overview**: Vendor detection consensus - how many engines flagged it and what the distribution looks like.

3. **Threat Classification**: Malware family (if identified), attack vector, associated campaigns or threat actors.

4. **File Characteristics**: File type, size, first/last seen dates, distribution methods.

5. **Confidence Level**: Rate your confidence (High/Medium/Low) with explanation.

IMPORTANT: At the very end of your response, you MUST include a structured assessment line in exactly this format:
ASSESSMENT: [category] | [threat_level] | [confidence]

Where:
- category is exactly one of: browser, vpn, malware, tool, library, bot, suspicious, benign
- threat_level is exactly one of: critical, high, medium, low, none
- confidence is exactly one of: high, medium, low

For file hashes:
- Use "malware" when VT detections are significant (>10 engines) or malware family is identified
- Use "suspicious" when detections are low but present, or file is associated with threat reports
- Use "tool" for dual-use tools (penetration testing frameworks, etc.)
- Use "benign" when no detections and no threat associations are found`,

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

      let analysisText = data.content[0].text;

      // Validate response safety (applies to both JA4 and file hash paths)
      const validation = this.validateResponse(analysisText);
      if (!validation.safe) {
        console.warn('JAH: Response filtered for safety:', validation.reason);
        analysisText = 'Analysis filtered for safety. The AI response contained potentially harmful content and was blocked.\n\nASSESSMENT: suspicious | medium | low';
      }

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
   * Enrich a file hash with threat intelligence context
   * @param {string} hash - The file hash (MD5, SHA1, SHA256)
   * @param {string} hashType - The hash type
   * @param {object} threatContext - Results from ThreatIntelClient.queryAll()
   * @param {object} knownMatch - Any known match from local database
   * @returns {Promise<object>}
   */
  async enrichFileHash(hash, hashType, threatContext, knownMatch = null) {
    const apiKey = await this.getApiKey();
    if (!apiKey) {
      throw new Error('API key not configured. Please set your Claude API key in the extension options.');
    }

    const model = await this.getModel();

    let userMessage = `Analyze this file hash and provide your threat assessment.\n\n`;
    userMessage += `**Hash:** \`${hash}\`\n`;
    userMessage += `**Hash Type:** ${hashType}\n`;

    // VirusTotal results
    const vt = threatContext?.virusTotal;
    if (vt && vt.found) {
      userMessage += `\n**VirusTotal Results:**\n`;
      userMessage += `- Detection: ${vt.maliciousCount}/${vt.totalEngines} engines flagged as malicious\n`;
      userMessage += `- Suspicious: ${vt.suspiciousCount} engines flagged as suspicious\n`;
      if (vt.meaningfulName) userMessage += `- File Name: ${vt.meaningfulName}\n`;
      if (vt.fileType) userMessage += `- File Type: ${vt.fileType}\n`;
      if (vt.fileSize) userMessage += `- File Size: ${vt.fileSize} bytes\n`;
      if (vt.firstSeen) userMessage += `- First Seen: ${vt.firstSeen}\n`;
      if (vt.lastSeen) userMessage += `- Last Seen: ${vt.lastSeen}\n`;
      if (vt.tags && vt.tags.length > 0) userMessage += `- Tags: ${vt.tags.join(', ')}\n`;
      if (vt.vendorDetections && vt.vendorDetections.length > 0) {
        userMessage += `\n**Top Vendor Detections:**\n`;
        vt.vendorDetections.slice(0, 10).forEach(d => {
          userMessage += `- ${d.vendor}: ${d.result} (${d.category})\n`;
        });
      }
    } else if (vt) {
      userMessage += `\n**VirusTotal:** ${vt.error || 'Hash not found in VirusTotal'}\n`;
    }

    // MalwareBazaar results
    const mb = threatContext?.malwareBazaar;
    if (mb && mb.found) {
      userMessage += `\n**MalwareBazaar (abuse.ch) Results:**\n`;
      if (mb.signature) userMessage += `- Malware Family: ${mb.signature}\n`;
      if (mb.fileName) userMessage += `- File Name: ${mb.fileName}\n`;
      if (mb.fileType) userMessage += `- File Type: ${mb.fileType}\n`;
      if (mb.tags && mb.tags.length > 0) userMessage += `- Tags: ${mb.tags.join(', ')}\n`;
      if (mb.firstSeen) userMessage += `- First Seen: ${mb.firstSeen}\n`;
      if (mb.deliveryMethod) userMessage += `- Delivery Method: ${mb.deliveryMethod}\n`;
      if (mb.reporter) userMessage += `- Reporter: ${mb.reporter}\n`;
    } else if (mb) {
      userMessage += `\n**MalwareBazaar:** ${mb.error || 'Hash not found'}\n`;
    }

    // AlienVault OTX results
    const otx = threatContext?.alienVaultOTX;
    if (otx && otx.found) {
      userMessage += `\n**AlienVault OTX Results:**\n`;
      userMessage += `- Pulse Count: ${otx.pulseCount} threat reports reference this hash\n`;
      if (otx.pulseNames && otx.pulseNames.length > 0) {
        userMessage += `- Related Reports: ${otx.pulseNames.join(', ')}\n`;
      }
      if (otx.malwareFamilies && otx.malwareFamilies.length > 0) {
        userMessage += `- Malware Families: ${otx.malwareFamilies.join(', ')}\n`;
      }
    } else if (otx) {
      userMessage += `\n**AlienVault OTX:** ${otx.error || 'Hash not found'}\n`;
    }

    // Known match from local database
    if (knownMatch) {
      userMessage += `\n**Local Database Match:**\n- Name: ${knownMatch.name}\n- Category: ${knownMatch.category}\n- Description: ${knownMatch.description || 'N/A'}\n`;
    }

    // Errors from threat intel lookups
    if (threatContext?.errors && threatContext.errors.length > 0) {
      userMessage += `\n**Note:** Some lookups failed: ${threatContext.errors.map(e => `${e.source}: ${e.error}`).join('; ')}\n`;
    }

    userMessage += `\nProvide your analysis starting with a 3-sentence Summary.`;

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
          system: this.FILE_HASH_SYSTEM_PROMPT,
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
        }
        throw new Error(`API error (${response.status}): ${errorData.error?.message || 'Unknown error'}`);
      }

      const data = await response.json();

      if (!data.content || !data.content[0]) {
        throw new Error('Invalid response from Claude API');
      }

      let analysisText = data.content[0].text;

      // Validate response for safety
      const validation = this.validateResponse(analysisText);
      if (!validation.safe) {
        console.warn('JAH: Response filtered for safety:', validation.reason);
        analysisText = `**Response filtered for safety.**\n\n${validation.reason}\n\nPlease review the raw threat intelligence data in the sections above.\n\nASSESSMENT: suspicious | medium | low`;
      }

      const summary = this.extractSummary(analysisText);
      const assessment = this.extractAssessment(analysisText);

      return {
        success: true,
        summary: summary,
        analysis: analysisText,
        assessment: assessment,
        model: data.model,
        usage: data.usage,
        timestamp: new Date().toISOString(),
        isFileHash: true
      };
    } catch (error) {
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        throw new Error('Network error. Please check your internet connection.');
      }
      throw error;
    }
  },

  /**
   * Validate Claude response for safety
   * Checks for forbidden content patterns
   * @param {string} text - The response text to validate
   * @returns {object} - { safe: boolean, reason: string|null }
   */
  validateResponse(text) {
    if (!text) return { safe: true, reason: null };

    const forbiddenPatterns = [
      { pattern: /(?:wget|curl|download)\s+.*(?:malware|payload|sample|\.exe|\.dll)/i, reason: 'Contains download instructions for potentially malicious files' },
      { pattern: /(?:execute|run|detonate)\s+.*(?:payload|sample|binary|malware)/i, reason: 'Contains execution instructions for potentially malicious content' },
      { pattern: /(?:rm\s+-rf|format\s+c:|del\s+\/[sf])/i, reason: 'Contains destructive system commands' },
      { pattern: /(?:reverse.?shell|bind.?shell|msfvenom|msfconsole)/i, reason: 'Contains exploit framework commands' },
      { pattern: /(?:base64\s+-d|eval\s*\(|exec\s*\().*(?:payload|shell|reverse)/i, reason: 'Contains encoded payload execution' }
    ];

    for (const { pattern, reason } of forbiddenPatterns) {
      if (pattern.test(text)) {
        return { safe: false, reason };
      }
    }

    return { safe: true, reason: null };
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
