const fs = require('fs');
const path = require('path');
const os = require('os');
const { logger } = require('../src/utils/logger');

// Use the same temp directory as cache.js
const CACHE_DIR = process.env.DEPSCAN_CACHE_DIR || path.join(os.tmpdir(), 'depscan-cache');
const CACHE_FILE = path.join(CACHE_DIR, 'cache.json');

function clearCache() {
  if (fs.existsSync(CACHE_FILE)) {
    fs.unlinkSync(CACHE_FILE);
    logger.info('🧹 Cache cleared successfully');
  } else {
    logger.info('📦 No cache file found');
  }
  
  // Also clear backup files
  if (fs.existsSync(CACHE_DIR)) {
    const backupFiles = fs.readdirSync(CACHE_DIR)
      .filter(f => f.startsWith('cache.json.backup'));
    
    for (const file of backupFiles) {
      fs.unlinkSync(path.join(CACHE_DIR, file));
      logger.info(`🧹 Removed backup: ${file}`);
    }
  }
}

if (require.main === module) {
  clearCache();
}

module.exports = clearCache;