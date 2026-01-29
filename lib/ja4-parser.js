/**
 * JA4 Fingerprint Parser and Validator
 * Supports JA4, JA4S, JA4H, JA4X, JA4SSH, JA4T, JA4TS fingerprints
 */

const JA4Parser = {
  // Regex patterns for different JA4 types
  patterns: {
    // JA4: TLS client fingerprint - t13d1516h2_8daaf6152771_b0da82dd1658
    JA4: /^[tq][0-9]{2}[di][0-9]{4,6}[a-z0-9]{0,4}_[a-f0-9]{12}_[a-f0-9]{12}$/i,

    // JA4S: TLS server fingerprint - t130200_1301_234ea6891581
    JA4S: /^[tq][0-9]{6}_[a-f0-9]{4}_[a-f0-9]{12}$/i,

    // JA4H: HTTP client fingerprint - ge11cn20enus_60ca1bd65281_ac95b44401d9_8df6a44f726c
    // Format: method(2) + version(2) + flags(2) + headerCount(2) + acceptLang(4) + 3 hashes
    JA4H: /^[a-z]{2}[0-9]{2}[a-z]{2}[0-9]{2}[a-z]{4}_[a-f0-9]{12}_[a-f0-9]{12}_[a-f0-9]{12}$/i,

    // JA4X: X.509 certificate fingerprint - 2f8a8b8c8d8e_2f8a8b8c8d8e_2f8a8b8c8d8e
    JA4X: /^[a-f0-9]{12}_[a-f0-9]{12}_[a-f0-9]{12}$/i,

    // JA4SSH: SSH fingerprint - c]s]p[_i]o]
    JA4SSH: /^c[0-9]{1,4}s[0-9]{1,4}p[0-9]{1,4}_[io][0-9]{1,4}[io][0-9]{1,4}$/i,

    // JA4T: TCP client fingerprint - 64240_2-1-3-1-1-4_1460_8
    JA4T: /^[0-9]+_[0-9\-]+_[0-9]+_[0-9]+$/,

    // JA4TS: TCP server fingerprint - similar to JA4T
    JA4TS: /^[0-9]+_[0-9\-]+_[0-9]+_[0-9]+_[rs]$/
  },

  /**
   * Detect the type of JA4 fingerprint
   * @param {string} hash - The fingerprint hash to analyze
   * @returns {string|null} - The fingerprint type or null if not recognized
   */
  detectType(hash) {
    if (!hash || typeof hash !== 'string') return null;

    const trimmed = hash.trim();

    for (const [type, pattern] of Object.entries(this.patterns)) {
      if (pattern.test(trimmed)) {
        return type;
      }
    }

    // Generic fallback check for JA4-like patterns
    if (/^[a-z][0-9]{2}[a-z][0-9]{4,}[a-z0-9]*_[a-f0-9]{12}_[a-f0-9]{12}$/i.test(trimmed)) {
      return 'JA4';
    }

    return null;
  },

  /**
   * Validate if a string is a valid JA4 fingerprint
   * @param {string} hash - The hash to validate
   * @returns {boolean}
   */
  isValid(hash) {
    return this.detectType(hash) !== null;
  },

  /**
   * Parse a JA4 fingerprint and extract its components
   * @param {string} hash - The fingerprint hash
   * @returns {object|null} - Parsed components or null if invalid
   */
  parse(hash) {
    const type = this.detectType(hash);
    if (!type) return null;

    const trimmed = hash.trim();

    switch (type) {
      case 'JA4':
        return this.parseJA4(trimmed);
      case 'JA4S':
        return this.parseJA4S(trimmed);
      case 'JA4H':
        return this.parseJA4H(trimmed);
      case 'JA4X':
        return this.parseJA4X(trimmed);
      case 'JA4SSH':
        return this.parseJA4SSH(trimmed);
      case 'JA4T':
      case 'JA4TS':
        return this.parseJA4T(trimmed, type);
      default:
        return { type, raw: trimmed };
    }
  },

  /**
   * Parse JA4 TLS client fingerprint
   */
  parseJA4(hash) {
    const parts = hash.split('_');
    if (parts.length !== 3) return { type: 'JA4', raw: hash };

    const prefix = parts[0];
    const protocol = prefix[0] === 't' ? 'TCP' : 'QUIC';
    const tlsVersion = prefix.substring(1, 3);
    const sniPresent = prefix[3] === 'd' ? 'Domain SNI' : 'IP SNI';
    const cipherCount = prefix.substring(4, 6);
    const extensionCount = prefix.substring(6, 8);
    const alpn = prefix.substring(8) || 'unknown';

    return {
      type: 'JA4',
      raw: hash,
      components: {
        protocol,
        tlsVersion: this.decodeTLSVersion(tlsVersion),
        sniPresent,
        cipherCount: parseInt(cipherCount, 10),
        extensionCount: parseInt(extensionCount, 10),
        alpn: this.decodeALPN(alpn),
        cipherHash: parts[1],
        extensionHash: parts[2]
      }
    };
  },

  /**
   * Parse JA4S TLS server fingerprint
   */
  parseJA4S(hash) {
    const parts = hash.split('_');
    if (parts.length !== 3) return { type: 'JA4S', raw: hash };

    const prefix = parts[0];
    const protocol = prefix[0] === 't' ? 'TCP' : 'QUIC';
    const tlsVersion = prefix.substring(1, 3);
    const extensionCount = prefix.substring(3, 5);
    const alpn = prefix.substring(5, 7);

    return {
      type: 'JA4S',
      raw: hash,
      components: {
        protocol,
        tlsVersion: this.decodeTLSVersion(tlsVersion),
        extensionCount: parseInt(extensionCount, 10),
        alpn: this.decodeALPN(alpn),
        chosenCipher: parts[1],
        extensionHash: parts[2]
      }
    };
  },

  /**
   * Parse JA4H HTTP client fingerprint
   */
  parseJA4H(hash) {
    const parts = hash.split('_');
    if (parts.length !== 4) return { type: 'JA4H', raw: hash };

    const prefix = parts[0];
    const httpMethod = prefix.substring(0, 2);
    const httpVersion = prefix.substring(2, 4);
    const cookiePresent = prefix[4];
    const refererPresent = prefix[5];
    const headerCount = prefix.substring(6, 8);
    const acceptLang = prefix.substring(8, 12);

    return {
      type: 'JA4H',
      raw: hash,
      components: {
        httpMethod: this.decodeHTTPMethod(httpMethod),
        httpVersion: this.decodeHTTPVersion(httpVersion),
        hasCookie: cookiePresent === 'c',
        hasReferer: refererPresent === 'r',
        headerCount: parseInt(headerCount, 10),
        acceptLanguage: acceptLang || 'none',
        headerHash: parts[1],
        cookieHash: parts[2],
        headerValueHash: parts[3]
      }
    };
  },

  /**
   * Parse JA4X X.509 certificate fingerprint
   */
  parseJA4X(hash) {
    const parts = hash.split('_');
    if (parts.length !== 3) return { type: 'JA4X', raw: hash };

    return {
      type: 'JA4X',
      raw: hash,
      components: {
        issuerHash: parts[0],
        subjectHash: parts[1],
        extensionHash: parts[2]
      }
    };
  },

  /**
   * Parse JA4SSH fingerprint
   */
  parseJA4SSH(hash) {
    const parts = hash.split('_');
    if (parts.length !== 2) return { type: 'JA4SSH', raw: hash };

    const clientMatch = parts[0].match(/c(\d+)s(\d+)p(\d+)/i);
    const serverMatch = parts[1].match(/([io])(\d+)([io])(\d+)/i);

    if (!clientMatch || !serverMatch) {
      return { type: 'JA4SSH', raw: hash };
    }

    return {
      type: 'JA4SSH',
      raw: hash,
      components: {
        clientPackets: parseInt(clientMatch[1], 10),
        serverPackets: parseInt(clientMatch[2], 10),
        payloadSize: parseInt(clientMatch[3], 10),
        direction1: serverMatch[1] === 'i' ? 'inbound' : 'outbound',
        size1: parseInt(serverMatch[2], 10),
        direction2: serverMatch[3] === 'i' ? 'inbound' : 'outbound',
        size2: parseInt(serverMatch[4], 10)
      },
      analysis: {
        isInteractive: this.analyzeSSHInteractivity(parts)
      }
    };
  },

  /**
   * Parse JA4T/JA4TS TCP fingerprint
   */
  parseJA4T(hash, type) {
    const parts = hash.split('_');

    return {
      type,
      raw: hash,
      components: {
        windowSize: parts[0],
        tcpOptions: parts[1],
        mss: parts[2],
        windowScale: parts[3],
        isResponse: type === 'JA4TS' && parts[4] === 'r'
      }
    };
  },

  /**
   * Analyze SSH session for interactivity
   */
  analyzeSSHInteractivity(parts) {
    // Interactive sessions typically have small, frequent packets
    // Automated/scripted sessions have larger, less frequent packets
    const clientMatch = parts[0].match(/c(\d+)s(\d+)p(\d+)/i);
    if (!clientMatch) return 'unknown';

    const payloadSize = parseInt(clientMatch[3], 10);

    if (payloadSize < 100) return 'likely interactive (small packets)';
    if (payloadSize > 1000) return 'likely automated/scripted (large packets)';
    return 'uncertain';
  },

  /**
   * Decode TLS version number
   */
  decodeTLSVersion(code) {
    const versions = {
      '10': 'TLS 1.0',
      '11': 'TLS 1.1',
      '12': 'TLS 1.2',
      '13': 'TLS 1.3',
      '00': 'Unknown'
    };
    return versions[code] || `TLS ${code}`;
  },

  /**
   * Decode ALPN protocol
   */
  decodeALPN(code) {
    const protocols = {
      'h1': 'HTTP/1.1',
      'h2': 'HTTP/2',
      'h3': 'HTTP/3',
      'd1': 'DNS over TLS',
      '00': 'None/Unknown'
    };
    return protocols[code] || code;
  },

  /**
   * Decode HTTP method
   */
  decodeHTTPMethod(code) {
    const methods = {
      'ge': 'GET',
      'po': 'POST',
      'pu': 'PUT',
      'de': 'DELETE',
      'he': 'HEAD',
      'op': 'OPTIONS',
      'pa': 'PATCH'
    };
    return methods[code] || code.toUpperCase();
  },

  /**
   * Decode HTTP version
   */
  decodeHTTPVersion(code) {
    const versions = {
      '10': 'HTTP/1.0',
      '11': 'HTTP/1.1',
      '20': 'HTTP/2',
      '30': 'HTTP/3'
    };
    return versions[code] || `HTTP ${code}`;
  }
};

// Export for use in other scripts (if in module context)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = JA4Parser;
}
