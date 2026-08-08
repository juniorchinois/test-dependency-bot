// tests/setup.js
const nock = require('nock');
const path = require('path');
const fs = require('fs');

// Disable real network connections
nock.disableNetConnect();

// Setup environment variables
process.env.APP_ID = '123456';
process.env.WEBHOOK_SECRET = 'test-secret';
process.env.PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAu7CkM8dF5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x
8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x
8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x
8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x
8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x
8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x
8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x
8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x
8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x8n5x
-----END RSA PRIVATE KEY-----`;
process.env.NODE_ENV = 'test';
process.env.SEVERITY_THRESHOLD = 'HIGH';

// Mock logger
jest.mock('../src/utils/logger', () => ({
  logger: { 
    info: jest.fn(), 
    error: jest.fn(), 
    warn: jest.fn(), 
    debug: jest.fn(), 
    success: jest.fn(),
    emoji: jest.fn()
  }
}));

// Mock cache
jest.mock('../src/utils/cache', () => ({
  getCached: jest.fn().mockReturnValue(null),
  setCached: jest.fn(),
  initialize: jest.fn(),
  shutdown: jest.fn(),
  getCacheStats: jest.fn().mockReturnValue({ totalEntries: 0 })
}));

// Mock config for tests
jest.mock('../src/config', () => ({
  severityThreshold: 'HIGH',
  cacheTTL: 86400000,
  maxDependencies: 100,
  ignoredPackages: [],
  apiTimeout: 30000,
  maxRetries: 3,
  retryDelay: 1000,
  skipForks: true,
  alwaysCreateNewComment: false,
  removeOldComments: false,
  osvApiUrl: 'https://api.osv.dev/v1/query',
  ecosystems: {
    npm: true,
    pip: true,
    yarn: false,
    poetry: false
  }
}));

// Clean up after each test
afterEach(() => {
  nock.cleanAll();
  jest.clearAllMocks();
});

// Set timeout for tests
jest.setTimeout(10000);

// Create test directories if needed
const testDirs = ['data', 'logs'];
for (const dir of testDirs) {
  const dirPath = path.join(__dirname, '..', dir);
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}