// src/config.js
require('dotenv').config();
const { logger } = require('./utils/logger');

// Cache TTL in seconds from .env, convert to milliseconds
const cacheTTLSeconds = parseInt(process.env.CACHE_TTL, 10);
const cacheTTL = Number.isFinite(cacheTTLSeconds) && cacheTTLSeconds > 0
  ? cacheTTLSeconds * 1000
  : 86400000; // 1 day default

const config = {
  // Severity threshold
  severityThreshold: (process.env.SEVERITY_THRESHOLD || 'HIGH').toUpperCase(),
  
  // Cache configuration
  cacheTTL: cacheTTL,
  
  // Dependencies limit
  maxDependencies: parseInt(process.env.MAX_DEPENDENCIES, 10) || 100,
  
  // Ignored packages (comma-separated)
  ignoredPackages: process.env.IGNORED_PACKAGES
    ? process.env.IGNORED_PACKAGES.split(',').map(p => p.trim()).filter(Boolean)
    : [],
  
  // API settings
  apiTimeout: parseInt(process.env.API_TIMEOUT, 10) || 30000,
  maxRetries: parseInt(process.env.MAX_RETRIES, 10) || 3,
  retryDelay: parseInt(process.env.RETRY_DELAY, 10) || 1000,
  
  // Repository settings
  skipForks: process.env.SKIP_FORKS !== 'false',
  
  // Comment management
  alwaysCreateNewComment: process.env.ALWAYS_CREATE_NEW_COMMENT === 'true',
  removeOldComments: process.env.REMOVE_OLD_COMMENTS === 'true',
  
  // API URLs
  osvApiUrl: process.env.OSV_API_URL || 'https://api.osv.dev/v1/query',
  npmRegistryUrl: process.env.NPM_REGISTRY_URL || 'https://registry.npmjs.org',
  pypiRegistryUrl: process.env.PYPI_REGISTRY_URL || 'https://pypi.org/pypi',
  
  // Ecosystem support
  ecosystems: {
    npm: process.env.ENABLE_NPM !== 'false',
    pip: process.env.ENABLE_PIP !== 'false',
    yarn: process.env.ENABLE_YARN === 'true',
    poetry: process.env.ENABLE_POETRY === 'true'
  }
};

// Validate configuration
const validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
if (!validSeverities.includes(config.severityThreshold)) {
  logger.warn(`Invalid SEVERITY_THRESHOLD: ${config.severityThreshold}. Using 'HIGH' as default.`);
  config.severityThreshold = 'HIGH';
}

if (config.maxDependencies < 1 || config.maxDependencies > 1000) {
  logger.warn(`Invalid MAX_DEPENDENCIES: ${config.maxDependencies}. Using 100 as default.`);
  config.maxDependencies = 100;
}

// Log configuration on startup
logger.debug('Configuration loaded:', {
  severityThreshold: config.severityThreshold,
  cacheTTL: config.cacheTTL / 1000 + 's',
  maxDependencies: config.maxDependencies,
  ignoredPackages: config.ignoredPackages,
  skipForks: config.skipForks,
  ecosystems: config.ecosystems
});

module.exports = config;