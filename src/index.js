// src/index.js - Simple entry point that imports from app.js
const { Probot } = require('probot');
const botApp = require('./app');

// Wrap the app for Probot
module.exports = (app) => {
  botApp(app);
};

// For local development
if (require.main === module) {
  const probot = new Probot({
    appId: process.env.APP_ID,
    privateKey: process.env.PRIVATE_KEY,
    secret: process.env.WEBHOOK_SECRET
  });

  probot.load(botApp);
  probot.start();
}