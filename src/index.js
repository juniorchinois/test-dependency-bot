// src/index.js - Supports both bot AND library
const { Probot } = require('probot');
const botApp = require('./app');

// Export as library (for programmatic use)
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
  runBot: (options = {}) => {
    const probot = new Probot({
      appId: options.appId || process.env.APP_ID,
      privateKey: options.privateKey || process.env.PRIVATE_KEY,
      secret: options.webhookSecret || process.env.WEBHOOK_SECRET,
      ...options
    });
    probot.load(botApp);
    return probot.start();
  }
};

// Export the bot function for Probot CLI (THIS IS THE KEY FIX)
module.exports = (app) => {
  // Load your actual bot app
  botApp(app);
};

// Also attach library exports to the function
Object.assign(module.exports, libraryExports);

// If run directly (node src/index.js), start bot
if (require.main === module) {
  const probot = new Probot({
    appId: process.env.APP_ID,
    privateKey: process.env.PRIVATE_KEY,
    secret: process.env.WEBHOOK_SECRET
  });
  probot.load(botApp);
  probot.start();
}