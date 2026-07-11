const fs = require('fs');
const path = require('path');
const { logger } = require('../src/utils/logger');

const CACHE_FILE = path.join(__dirname, '../data/cache.json');

function clearCache() {
  if (fs.existsSync(CACHE_FILE)) {
    fs.unlinkSync(CACHE_FILE);
    logger.info('🧹 Cache cleared successfully');
  } else {
    logger.info('📦 No cache file found');
  }
  
  // Also clear backup files
  const backupFiles = fs.readdirSync(path.dirname(CACHE_FILE))
    .filter(f => f.startsWith('cache.json.backup'));
  
  for (const file of backupFiles) {
    fs.unlinkSync(path.join(path.dirname(CACHE_FILE), file));
    logger.info(`🧹 Removed backup: ${file}`);
  }
}

if (require.main === module) {
  clearCache();
}

module.exports = clearCache;