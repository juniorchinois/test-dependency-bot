// src/index.js - Main entry point
const { Probot } = require('probot');
const botApp = require('./app');
const { logger } = require('./utils/logger');

// Export as library
const libraryExports = {
  botApp,
  scanNPM: require('./scanners/npm-scanner').scanNPM,
  scanPip: require('./scanners/pip-scanner').scanPip,
  getCached: require('./utils/cache').getCached,
  setCached: require('./utils/cache').setCached,
  logger: require('./utils/logger').logger,
  config: require('./config'),
  formatComment: require('./utils/github').formatComment,
  formatErrorComment: require('./utils/github').formatErrorComment,
  runBot: async (options = {}) => {
    const probot = new Probot({
      appId: options.appId || process.env.APP_ID,
      privateKey: options.privateKey || process.env.PRIVATE_KEY,
      secret: options.webhookSecret || process.env.WEBHOOK_SECRET,
      ...options
    });
    probot.load(botApp);
    const server = await probot.start();
    logger.info('🚀 Bot started successfully');
    return server;
  }
};

// Export bot function for Probot CLI
module.exports = (app) => {
  botApp(app);
};

// Attach library exports
Object.assign(module.exports, libraryExports);

// Run directly if main
if (require.main === module) {
  const probot = new Probot({
    appId: process.env.APP_ID,
    privateKey: process.env.PRIVATE_KEY,
    secret: process.env.WEBHOOK_SECRET
  });
  probot.load(botApp);
  probot.start().then(() => {
    logger.info('🚀 Bot started successfully');
  }).catch((error) => {
    logger.error('Failed to start bot:', error);
    process.exit(1);
  });
}