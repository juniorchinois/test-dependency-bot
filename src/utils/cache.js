const fs = require('fs');
const path = require('path');
const { logger } = require('./logger');

const CACHE_FILE = path.join(__dirname, '../../data/cache.json');
const MAX_CACHE_SIZE = 10000; // Maximum number of entries

// Ensure data directory exists
if (!fs.existsSync(path.dirname(CACHE_FILE))) {
  fs.mkdirSync(path.dirname(CACHE_FILE), { recursive: true });
}

// Initialize cache
let cache = {};
let cacheDirty = false;

function loadCache() {
  try {
    if (fs.existsSync(CACHE_FILE)) {
      const data = fs.readFileSync(CACHE_FILE, 'utf8');
      cache = JSON.parse(data);
      logger.info(`📦 Cache loaded with ${Object.keys(cache).length} entries`);
    } else {
      cache = {};
      logger.info('📦 New cache created');
    }
  } catch (error) {
    logger.error('Error loading cache:', error);
    cache = {};
  }
}

function saveCache() {
  if (!cacheDirty) return;
  
  try {
    // Limit cache size
    const keys = Object.keys(cache);
    if (keys.length > MAX_CACHE_SIZE) {
      // Sort by timestamp and keep only the most recent entries
      const sorted = keys.sort((a, b) => {
        const aTime = cache[a]?.timestamp || 0;
        const bTime = cache[b]?.timestamp || 0;
        return bTime - aTime;
      });
      
      const toKeep = sorted.slice(0, MAX_CACHE_SIZE);
      const newCache = {};
      for (const key of toKeep) {
        newCache[key] = cache[key];
      }
      cache = newCache;
    }

    fs.writeFileSync(CACHE_FILE, JSON.stringify(cache, null, 2));
    cacheDirty = false;
    logger.debug(`💾 Cache saved with ${Object.keys(cache).length} entries`);
  } catch (error) {
    logger.error('Error saving cache:', error);
  }
}

function getCached(key) {
  loadCache();
  const entry = cache[key];
  if (entry) {
    logger.debug(`Cache hit: ${key}`);
    return entry;
  }
  logger.debug(`Cache miss: ${key}`);
  return null;
}

function setCached(key, value) {
  loadCache();
  cache[key] = value;
  cacheDirty = true;
  
  // Save immediately for critical operations
  if (value.vulnerabilities?.length > 0) {
    saveCache();
  } else {
    // Otherwise, save after a delay
    clearTimeout(setCached._timeout);
    setCached._timeout = setTimeout(saveCache, 5000);
  }
}

function cleanCache() {
  loadCache();
  const now = Date.now();
  const weekAgo = now - 7 * 24 * 60 * 60 * 1000;
  let cleaned = false;
  
  for (const [key, value] of Object.entries(cache)) {
    if (value.timestamp < weekAgo) {
      delete cache[key];
      cleaned = true;
    }
  }
  
  if (cleaned) {
    cacheDirty = true;
    saveCache();
    logger.info(`🧹 Cache cleaned: removed entries older than 7 days`);
  }
}

// Stats methods
function getCacheStats() {
  loadCache();
  const total = Object.keys(cache).length;
  const timestamp = Date.now();
  
  let oldCount = 0;
  let freshCount = 0;
  
  for (const value of Object.values(cache)) {
    if (value.timestamp && timestamp - value.timestamp > 86400000) {
      oldCount++;
    } else {
      freshCount++;
    }
  }
  
  return {
    totalEntries: total,
    freshEntries: freshCount,
    oldEntries: oldCount,
    lastSave: fs.existsSync(CACHE_FILE) ? fs.statSync(CACHE_FILE).mtime : null
  };
}

// Initialize cache
loadCache();

// Clean cache every hour
setInterval(cleanCache, 60 * 60 * 1000);

// Save cache on process exit
process.on('exit', saveCache);
process.on('SIGINT', () => {
  saveCache();
  process.exit(0);
});

module.exports = { getCached, setCached, getCacheStats, cleanCache };