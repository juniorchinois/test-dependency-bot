// src/utils/cache.js
const fs = require('fs');
const path = require('path');
const { logger } = require('./logger');
const config = require('../config');

const CACHE_DIR = path.join(__dirname, '../../data');
const CACHE_FILE = path.join(CACHE_DIR, 'cache.json');
const MAX_CACHE_SIZE = 10000;

let cache = {};
let cacheDirty = false;
let initialized = false;
let saveTimeout = null;
let saveQueue = [];

function ensureCacheDir() {
  if (!fs.existsSync(CACHE_DIR)) {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
    logger.info(`📁 Created cache directory: ${CACHE_DIR}`);
  }
}

function initialize() {
  if (initialized) return;
  ensureCacheDir();
  loadCache();
  initialized = true;
  
  // Handle process exit
  process.on('exit', () => { saveCacheSync(); });
  process.on('SIGINT', () => { saveCacheSync(); process.exit(0); });
  process.on('SIGTERM', () => { saveCacheSync(); process.exit(0); });
  
  logger.info(`📦 Cache initialized with ${Object.keys(cache).length} entries`);
}

function loadCache() {
  try {
    if (fs.existsSync(CACHE_FILE)) {
      const data = fs.readFileSync(CACHE_FILE, 'utf8');
      const parsed = JSON.parse(data);
      
      // Validate cache entries and remove expired ones
      const now = Date.now();
      const ttl = config.cacheTTL || 86400000;
      const validEntries = {};
      
      for (const [key, value] of Object.entries(parsed)) {
        if (value.timestamp && (now - value.timestamp) < ttl) {
          validEntries[key] = value;
        }
      }
      
      cache = validEntries;
      logger.debug(`📦 Cache loaded with ${Object.keys(cache).length} valid entries (${Object.keys(parsed).length - Object.keys(cache).length} expired)`);
    } else {
      logger.debug('📦 No cache file found, starting fresh');
    }
  } catch (error) {
    logger.error('Error loading cache:', error);
    cache = {};
  }
}

function saveCacheSync() {
  if (!cacheDirty || !initialized) return;
  try {
    ensureCacheDir();
    
    // Limit cache size
    const keys = Object.keys(cache);
    if (keys.length > MAX_CACHE_SIZE) {
      const sorted = keys.sort((a, b) => (cache[b]?.timestamp || 0) - (cache[a]?.timestamp || 0));
      const newCache = {};
      for (const key of sorted.slice(0, MAX_CACHE_SIZE)) {
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

function saveCacheAsync() {
  if (!cacheDirty || !initialized) return;
  
  // Debounce saves
  clearTimeout(saveTimeout);
  saveTimeout = setTimeout(() => {
    saveCacheSync();
  }, 5000);
}

function getCached(key) {
  if (!initialized) initialize();
  
  const entry = cache[key];
  if (!entry) return null;
  
  // Check if expired
  const now = Date.now();
  const ttl = config.cacheTTL || 86400000;
  if (entry.timestamp && (now - entry.timestamp) > ttl) {
    delete cache[key];
    cacheDirty = true;
    return null;
  }
  
  return entry;
}

function setCached(key, value) {
  if (!initialized) initialize();
  
  // Ensure value has timestamp
  if (!value.timestamp) {
    value.timestamp = Date.now();
  }
  
  cache[key] = value;
  cacheDirty = true;
  saveCacheAsync();
}

function getCacheStats() {
  if (!initialized) initialize();
  const now = Date.now();
  const ttl = config.cacheTTL || 86400000;
  
  let validCount = 0;
  let expiredCount = 0;
  
  for (const [key, value] of Object.entries(cache)) {
    if (value.timestamp && (now - value.timestamp) < ttl) {
      validCount++;
    } else {
      expiredCount++;
    }
  }
  
  return {
    totalEntries: Object.keys(cache).length,
    validEntries: validCount,
    expiredEntries: expiredCount,
    maxSize: MAX_CACHE_SIZE,
    cacheFile: CACHE_FILE,
    cacheDir: CACHE_DIR,
    lastSave: fs.existsSync(CACHE_FILE) ? fs.statSync(CACHE_FILE).mtime : null,
    fileSize: fs.existsSync(CACHE_FILE) ? fs.statSync(CACHE_FILE).size : 0
  };
}

function shutdown() {
  saveCacheSync();
  logger.info('💾 Cache saved on shutdown');
}

function cleanCache() {
  cache = {};
  cacheDirty = true;
  saveCacheSync();
  logger.info('🧹 Cache cleaned');
}

function getCacheKeys() {
  if (!initialized) initialize();
  return Object.keys(cache);
}

function getCacheEntry(key) {
  if (!initialized) initialize();
  return cache[key] || null;
}

module.exports = { 
  getCached, 
  setCached, 
  getCacheStats, 
  initialize, 
  shutdown,
  cleanCache,
  getCacheKeys,
  getCacheEntry
};