// tests/setup.js - Jest setup file
const nock = require('nock');

// Disable real network requests during tests
nock.disableNetConnect();

// Mock environment variables
process.env.APP_ID = '123456';
process.env.WEBHOOK_SECRET = 'test-secret';
process.env.PRIVATE_KEY = 'test-private-key';
process.env.NODE_ENV = 'test';

// Global mocks
jest.mock('../src/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
    success: jest.fn()
  }
}));

// Clean up after each test
afterEach(() => {
  nock.cleanAll();
});

// Timeout for tests
jest.setTimeout(10000);