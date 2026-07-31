const fs = require('fs');
const path = require('path');
const os = require('os');
const { logger } = require('./logger');

// Use temp directory instead of node_modules
const CACHE_DIR = process.env.DEPSCAN_CACHE_DIR || path.join(os.tmpdir(), 'depscan-cache');
const CACHE_FILE = path.join(CACHE_DIR, 'cache.json');
const MAX_CACHE_SIZE = 10000;

// LAZY INITIALIZATION - NOT on require()
let cache = {};
let cacheDirty = false;
let initialized = false;
let saveTimeout = null;
let cleanupInterval = null;
let signalHandlersRegistered = false;

function ensureCacheDir() {
  if (!fs.existsSync(CACHE_DIR)) {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
  }
}

function loadCache() {
  if (!initialized) return;
  try {
    if (fs.existsSync(CACHE_FILE)) {
      const data = fs.readFileSync(CACHE_FILE, 'utf8');
      cache = JSON.parse(data);
      logger.debug(`📦 Cache loaded with ${Object.keys(cache).length} entries`);
    }
  } catch (error) {
    logger.error('Error loading cache:', error);
    cache = {};
  }
}

function saveCache() {
  if (!cacheDirty || !initialized) return;
  try {
    ensureCacheDir();
    const keys = Object.keys(cache);
    if (keys.length > MAX_CACHE_SIZE) {
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

// NEW: Explicit initialization function
function initialize() {
  if (initialized) return;
  ensureCacheDir();
  loadCache();
  initialized = true;
  
  // .unref() so it doesn't block process exit
  if (!cleanupInterval) {
    cleanupInterval = setInterval(cleanCache, 60 * 60 * 1000);
    cleanupInterval.unref();
  }
  
  if (!signalHandlersRegistered) {
    process.on('exit', saveCache);
    process.on('SIGINT', () => {
      saveCache();
      process.exit(0);
    });
    signalHandlersRegistered = true;
  }
}

function getCached(key) {
  if (!initialized) initialize(); // Lazy init
  const entry = cache[key];
  if (entry) {
    logger.debug(`Cache hit: ${key}`);
    return entry;
  }
  logger.debug(`Cache miss: ${key}`);
  return null;
}

function setCached(key, value) {
  if (!initialized) initialize(); // Lazy init
  cache[key] = value;
  cacheDirty = true;
  if (value.vulnerabilities?.length > 0) {
    saveCache();
  } else {
    clearTimeout(saveTimeout);
    saveTimeout = setTimeout(saveCache, 5000);
    saveTimeout.unref(); // Don't block process exit
  }
}

function cleanCache() {
  if (!initialized) return;
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
    logger.debug(`🧹 Cache cleaned: removed entries older than 7 days`);
  }
}

function getCacheStats() {
  if (!initialized) initialize();
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
    cacheDir: CACHE_DIR,
    cacheFile: CACHE_FILE,
    lastSave: fs.existsSync(CACHE_FILE) ? fs.statSync(CACHE_FILE).mtime : null
  };
}

// NEW: Clean shutdown
function shutdown() {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
  }
  saveCache();
}

// REMOVED: No top-level loadCache(), setInterval(), or process.on()
// All of that is now inside initialize()

module.exports = { 
  getCached, 
  setCached, 
  getCacheStats, 
  cleanCache,
  initialize,  // NEW: Export init function
  shutdown,    // NEW: Export shutdown function
  reset: () => {
    if (cleanupInterval) {
      clearInterval(cleanupInterval);
      cleanupInterval = null;
    }
    clearTimeout(saveTimeout);
    cache = {};
    cacheDirty = false;
    initialized = false;
    signalHandlersRegistered = false;
  }
};