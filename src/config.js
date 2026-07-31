require('dotenv').config();

module.exports = {
  // Severity threshold
  severityThreshold: process.env.SEVERITY_THRESHOLD || 'HIGH',
  
  // Cache TTL in milliseconds (default: 24 hours)
  cacheTTL: parseInt(process.env.CACHE_TTL) || 86400000,
  
  // Maximum dependencies to check per scan
  maxDependencies: parseInt(process.env.MAX_DEPENDENCIES) || 100,
  
  // Ignored packages
  ignoredPackages: process.env.IGNORED_PACKAGES?.split(',').map(p => p.trim()) || [],
  
  // API timeout in milliseconds
  apiTimeout: parseInt(process.env.API_TIMEOUT) || 15000,
  
  // Skip forks
 skipForks: process.env.SKIP_FORKS !== 'false',
  
  // Always create new comment instead of updating
  alwaysCreateNewComment: process.env.ALWAYS_CREATE_NEW_COMMENT === 'true',
  
  // Remove old comments when no vulnerabilities found
  removeOldComments: process.env.REMOVE_OLD_COMMENTS === 'true',
  
  // OSV API URL
  osvApiUrl: process.env.OSV_API_URL || 'https://api.osv.dev/v1/query',
  
  // NPM registry URL
  npmRegistryUrl: process.env.NPM_REGISTRY_URL || 'https://registry.npmjs.org',
  
  // PyPI registry URL
  pypiRegistryUrl: process.env.PYPI_REGISTRY_URL || 'https://pypi.org/pypi',
  
  // Maximum retries for API calls
  maxRetries: parseInt(process.env.MAX_RETRIES) || 3,
  
  // Retry delay in milliseconds
  retryDelay: parseInt(process.env.RETRY_DELAY) || 1000,
  
  // Enable/disable specific ecosystems
  ecosystems: {
    npm: process.env.ENABLE_NPM !== 'false',
    pip: process.env.ENABLE_PIP !== 'false',
    yarn: process.env.ENABLE_YARN !== 'false',
    poetry: process.env.ENABLE_POETRY !== 'false'
  }
};