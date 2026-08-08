const fs = require('fs');
const path = require('path');
const { logger } = require('../src/utils/logger');

const CACHE_DIR = path.join(__dirname, '../data');
const CACHE_FILE = path.join(CACHE_DIR, 'cache.json');

function clearCache() {
  if (fs.existsSync(CACHE_FILE)) {
    fs.unlinkSync(CACHE_FILE);
    logger.info('🧹 Cache cleared successfully');
  } else {
    logger.info('📦 No cache file found');
  }
  
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