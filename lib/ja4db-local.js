/**
 * JA4DB Local Database Manager
 * Manages local IndexedDB copy of JA4 Database for instant lookups
 */

const JA4DBLocal = {
  DB_NAME: 'JAH_JA4DB',
  DB_VERSION: 1,
  STORE_NAME: 'fingerprints',
  META_STORE: 'metadata',
  DOWNLOAD_URL: 'https://ja4db.com/api/download/',

  db: null,
  isInitializing: false,
  initPromise: null,

  /**
   * Initialize the local database
   */
  async init() {
    if (this.db) return this.db;
    if (this.isInitializing) return this.initPromise;

    this.isInitializing = true;
    this.initPromise = this._openDatabase();

    try {
      this.db = await this.initPromise;
      console.log('JAH: Local JA4DB initialized');
      return this.db;
    } finally {
      this.isInitializing = false;
    }
  },

  /**
   * Open or create the IndexedDB database
   */
  _openDatabase() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.DB_NAME, this.DB_VERSION);

      request.onerror = () => {
        console.error('JAH: Failed to open IndexedDB:', request.error);
        reject(request.error);
      };

      request.onsuccess = () => {
        resolve(request.result);
      };

      request.onupgradeneeded = (event) => {
        const db = event.target.result;

        // Create fingerprints store with indexes
        if (!db.objectStoreNames.contains(this.STORE_NAME)) {
          const store = db.createObjectStore(this.STORE_NAME, { keyPath: 'id', autoIncrement: true });

          // Create indexes for each fingerprint type
          store.createIndex('ja4', 'ja4_fingerprint', { unique: false });
          store.createIndex('ja4s', 'ja4s_fingerprint', { unique: false });
          store.createIndex('ja4h', 'ja4h_fingerprint', { unique: false });
          store.createIndex('ja4x', 'ja4x_fingerprint', { unique: false });
          store.createIndex('ja4t', 'ja4t_fingerprint', { unique: false });
          store.createIndex('ja4ts', 'ja4ts_fingerprint', { unique: false });
          store.createIndex('ja4ssh', 'ja4ssh_fingerprint', { unique: false });
          store.createIndex('contentHash', 'contentHash', { unique: false });

          console.log('JAH: Created fingerprints store with indexes');
        }

        // Create metadata store for sync info
        if (!db.objectStoreNames.contains(this.META_STORE)) {
          db.createObjectStore(this.META_STORE, { keyPath: 'key' });
          console.log('JAH: Created metadata store');
        }
      };
    });
  },

  /**
   * Generate a hash for record content (for diff detection)
   */
  _hashRecord(record) {
    const content = JSON.stringify({
      application: record.application,
      library: record.library,
      device: record.device,
      os: record.os,
      user_agent_string: record.user_agent_string,
      certificate_authority: record.certificate_authority,
      verified: record.verified,
      notes: record.notes,
      ja4_fingerprint: record.ja4_fingerprint,
      ja4s_fingerprint: record.ja4s_fingerprint,
      ja4h_fingerprint: record.ja4h_fingerprint,
      ja4x_fingerprint: record.ja4x_fingerprint,
      ja4t_fingerprint: record.ja4t_fingerprint,
      ja4ts_fingerprint: record.ja4ts_fingerprint
    });

    // Simple hash function (djb2)
    let hash = 5381;
    for (let i = 0; i < content.length; i++) {
      hash = ((hash << 5) + hash) + content.charCodeAt(i);
      hash = hash & hash; // Convert to 32bit integer
    }
    return hash.toString(16);
  },

  /**
   * Generate a unique key for a record based on its fingerprints
   */
  _getRecordKey(record) {
    // Combine all fingerprint fields to create a unique key
    return [
      record.ja4_fingerprint || '',
      record.ja4s_fingerprint || '',
      record.ja4h_fingerprint || '',
      record.ja4x_fingerprint || '',
      record.ja4t_fingerprint || '',
      record.ja4ts_fingerprint || '',
      record.application || '',
      record.library || ''
    ].join('|');
  },

  /**
   * Get sync metadata
   */
  async getMetadata() {
    await this.init();

    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(this.META_STORE, 'readonly');
      const store = tx.objectStore(this.META_STORE);
      const request = store.get('syncInfo');

      request.onsuccess = () => {
        resolve(request.result || {
          key: 'syncInfo',
          lastSync: null,
          recordCount: 0,
          version: null
        });
      };
      request.onerror = () => reject(request.error);
    });
  },

  /**
   * Update sync metadata
   */
  async updateMetadata(metadata) {
    await this.init();

    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(this.META_STORE, 'readwrite');
      const store = tx.objectStore(this.META_STORE);
      const request = store.put({ ...metadata, key: 'syncInfo' });

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  },

  /**
   * Check if database needs initial population
   */
  async needsInitialSync() {
    const metadata = await this.getMetadata();
    return !metadata.lastSync;
  },

  /**
   * Download and sync the JA4DB
   * @param {function} progressCallback - Called with progress updates
   * @returns {object} Sync results
   */
  async syncDatabase(progressCallback = null) {
    await this.init();

    const startTime = Date.now();
    const report = (message, progress = null) => {
      console.log(`JAH Sync: ${message}`);
      if (progressCallback) {
        progressCallback({ message, progress });
      }
    };

    report('Starting JA4DB sync...', 0);

    try {
      // Download the database
      report('Downloading JA4DB...', 5);
      const response = await fetch(this.DOWNLOAD_URL);

      if (!response.ok) {
        throw new Error(`Download failed: ${response.status}`);
      }

      report('Parsing database...', 20);
      const remoteData = await response.json();
      report(`Downloaded ${remoteData.length} records`, 30);

      // Get existing records for diff comparison
      report('Building diff...', 35);
      const existingRecords = await this._getAllRecordsAsMap();

      // Process records and find changes
      const toAdd = [];
      const toUpdate = [];
      const seenKeys = new Set();

      for (let i = 0; i < remoteData.length; i++) {
        const record = remoteData[i];
        const key = this._getRecordKey(record);
        const hash = this._hashRecord(record);
        seenKeys.add(key);

        const existing = existingRecords.get(key);

        if (!existing) {
          // New record
          toAdd.push({ ...record, contentHash: hash, recordKey: key });
        } else if (existing.contentHash !== hash) {
          // Changed record
          toUpdate.push({ ...record, contentHash: hash, recordKey: key, id: existing.id });
        }
        // Else: unchanged, skip

        if (i % 10000 === 0) {
          const progress = 35 + Math.floor((i / remoteData.length) * 30);
          report(`Processing records... ${i}/${remoteData.length}`, progress);
        }
      }

      // Find records to delete (exist locally but not in remote)
      const toDelete = [];
      for (const [key, record] of existingRecords) {
        if (!seenKeys.has(key)) {
          toDelete.push(record.id);
        }
      }

      report(`Changes: ${toAdd.length} new, ${toUpdate.length} updated, ${toDelete.length} removed`, 70);

      // Apply changes in batches
      if (toAdd.length > 0 || toUpdate.length > 0 || toDelete.length > 0) {
        report('Applying changes...', 75);
        await this._applyChanges(toAdd, toUpdate, toDelete, (progress) => {
          report('Writing to database...', 75 + Math.floor(progress * 20));
        });
      }

      // Update metadata
      const syncTime = new Date().toISOString();
      await this.updateMetadata({
        lastSync: syncTime,
        recordCount: remoteData.length,
        added: toAdd.length,
        updated: toUpdate.length,
        deleted: toDelete.length,
        syncDuration: Date.now() - startTime
      });

      report('Sync complete!', 100);

      return {
        success: true,
        lastSync: syncTime,
        recordCount: remoteData.length,
        added: toAdd.length,
        updated: toUpdate.length,
        deleted: toDelete.length,
        duration: Date.now() - startTime
      };

    } catch (error) {
      console.error('JAH Sync Error:', error);
      report(`Sync failed: ${error.message}`, -1);
      return {
        success: false,
        error: error.message
      };
    }
  },

  /**
   * Get all existing records as a Map keyed by recordKey
   */
  async _getAllRecordsAsMap() {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(this.STORE_NAME, 'readonly');
      const store = tx.objectStore(this.STORE_NAME);
      const request = store.getAll();

      request.onsuccess = () => {
        const map = new Map();
        for (const record of request.result) {
          map.set(record.recordKey, record);
        }
        resolve(map);
      };
      request.onerror = () => reject(request.error);
    });
  },

  /**
   * Apply changes to the database in batches
   */
  async _applyChanges(toAdd, toUpdate, toDelete, progressCallback) {
    const BATCH_SIZE = 1000;
    const totalOps = toAdd.length + toUpdate.length + toDelete.length;
    let completed = 0;

    // Process additions
    for (let i = 0; i < toAdd.length; i += BATCH_SIZE) {
      const batch = toAdd.slice(i, i + BATCH_SIZE);
      await this._batchWrite(batch, 'add');
      completed += batch.length;
      progressCallback(completed / totalOps);
    }

    // Process updates
    for (let i = 0; i < toUpdate.length; i += BATCH_SIZE) {
      const batch = toUpdate.slice(i, i + BATCH_SIZE);
      await this._batchWrite(batch, 'put');
      completed += batch.length;
      progressCallback(completed / totalOps);
    }

    // Process deletions
    for (let i = 0; i < toDelete.length; i += BATCH_SIZE) {
      const batch = toDelete.slice(i, i + BATCH_SIZE);
      await this._batchDelete(batch);
      completed += batch.length;
      progressCallback(completed / totalOps);
    }
  },

  /**
   * Batch write records
   */
  _batchWrite(records, method) {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(this.STORE_NAME, 'readwrite');
      const store = tx.objectStore(this.STORE_NAME);

      for (const record of records) {
        if (method === 'add') {
          store.add(record);
        } else {
          store.put(record);
        }
      }

      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  },

  /**
   * Batch delete records
   */
  _batchDelete(ids) {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(this.STORE_NAME, 'readwrite');
      const store = tx.objectStore(this.STORE_NAME);

      for (const id of ids) {
        store.delete(id);
      }

      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  },

  /**
   * Look up a fingerprint in the local database
   * @param {string} hash - The fingerprint hash
   * @param {string} type - The fingerprint type (JA4, JA4S, etc.)
   * @returns {object} Lookup result
   */
  async lookup(hash, type) {
    await this.init();

    const indexName = this._typeToIndex(type);
    if (!indexName) {
      return { found: false, hash, type, error: 'Unknown fingerprint type' };
    }

    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(this.STORE_NAME, 'readonly');
      const store = tx.objectStore(this.STORE_NAME);
      const index = store.index(indexName);
      const request = index.getAll(hash);

      request.onsuccess = () => {
        const records = request.result;

        if (records.length === 0) {
          resolve({
            found: false,
            hash,
            type,
            matches: []
          });
          return;
        }

        // Process results similar to JA4DBClient
        const processed = this._processResults(records, type, hash);

        resolve({
          found: true,
          hash,
          type,
          matchCount: records.length,
          matches: processed.matches,
          summary: processed.summary,
          source: 'local'
        });
      };

      request.onerror = () => reject(request.error);
    });
  },

  /**
   * Map fingerprint type to index name
   */
  _typeToIndex(type) {
    const map = {
      'JA4': 'ja4',
      'JA4S': 'ja4s',
      'JA4H': 'ja4h',
      'JA4X': 'ja4x',
      'JA4T': 'ja4t',
      'JA4TS': 'ja4ts',
      'JA4SSH': 'ja4ssh'
    };
    return map[type];
  },

  /**
   * Process results (similar to JA4DBClient.processResults)
   */
  _processResults(data, queriedType, queriedHash) {
    const applications = new Set();
    const libraries = new Set();
    const devices = new Set();
    const operatingSystems = new Set();
    const userAgents = new Set();
    const certificates = new Set();
    const directApplications = new Set();
    const relatedApplications = new Set();

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

      // Determine direct vs related applications
      let isDirectMatch = true;
      if (record.application) {
        if (queriedType === 'JA4S' && record.ja4_fingerprint) {
          isDirectMatch = false;
          relatedApplications.add(record.application);
        } else if (queriedType === 'JA4' || !record.ja4_fingerprint) {
          directApplications.add(record.application);
        } else if (record.ja4_fingerprint) {
          isDirectMatch = false;
          relatedApplications.add(record.application);
        } else {
          directApplications.add(record.application);
        }
      }

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
        isDirectMatch,
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
        directApplications: Array.from(directApplications),
        relatedApplications: Array.from(relatedApplications),
        libraries: Array.from(libraries),
        devices: Array.from(devices),
        operatingSystems: Array.from(operatingSystems),
        userAgents: Array.from(userAgents).slice(0, 5),
        certificates: Array.from(certificates),
        totalObservations,
        verifiedCount,
        totalRecords: data.length
      }
    };
  },

  /**
   * Get database statistics
   */
  async getStats() {
    await this.init();

    const metadata = await this.getMetadata();

    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(this.STORE_NAME, 'readonly');
      const store = tx.objectStore(this.STORE_NAME);
      const countRequest = store.count();

      countRequest.onsuccess = () => {
        resolve({
          recordCount: countRequest.result,
          lastSync: metadata.lastSync,
          lastSyncDuration: metadata.syncDuration,
          lastAdded: metadata.added,
          lastUpdated: metadata.updated,
          lastDeleted: metadata.deleted
        });
      };
      countRequest.onerror = () => reject(countRequest.error);
    });
  },

  /**
   * Clear the local database
   */
  async clearDatabase() {
    await this.init();

    return new Promise((resolve, reject) => {
      const tx = this.db.transaction([this.STORE_NAME, this.META_STORE], 'readwrite');

      tx.objectStore(this.STORE_NAME).clear();
      tx.objectStore(this.META_STORE).clear();

      tx.oncomplete = () => {
        console.log('JAH: Local database cleared');
        resolve();
      };
      tx.onerror = () => reject(tx.error);
    });
  }
};

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = JA4DBLocal;
}
