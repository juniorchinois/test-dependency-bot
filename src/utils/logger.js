// src/utils/logger.js
const winston = require('winston');
const path = require('path');
const fs = require('fs');

const logDir = path.join(__dirname, '../../logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

const logLevel = process.env.LOG_LEVEL || 'info';

// Custom format for console
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: 'HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    const metaStr = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
    return `${timestamp} [${level}] ${message}${metaStr}`;
  })
);

// Custom format for files
const fileFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json()
);

const logger = winston.createLogger({
  level: logLevel,
  format: fileFormat,
  defaultMeta: { service: 'dependency-bot' },
  transports: [
    new winston.transports.Console({
      format: consoleFormat,
      level: logLevel
    }),
    new winston.transports.File({
      filename: path.join(logDir, 'error.log'),
      level: 'error',
      maxsize: 10485760, // 10MB
      maxFiles: 5,
      format: fileFormat
    }),
    new winston.transports.File({
      filename: path.join(logDir, 'combined.log'),
      maxsize: 10485760, // 10MB
      maxFiles: 5,
      format: fileFormat
    })
  ]
});

// Add custom success method
logger.success = (message, meta = {}) => {
  logger.info(`✅ ${message}`, meta);
};

// Add custom methods for better readability
logger.start = (message, meta = {}) => {
  logger.info(`🚀 ${message}`, meta);
};

logger.warn = (message, meta = {}) => {
  logger.log({ level: 'warn', message: `⚠️ ${message}`, ...meta });
};

logger.error = (message, meta = {}) => {
  logger.log({ level: 'error', message: `❌ ${message}`, ...meta });
};

logger.debug = (message, meta = {}) => {
  logger.log({ level: 'debug', message: `🔍 ${message}`, ...meta });
};

// Add a method to log with emojis based on type
logger.emoji = (emoji, message, meta = {}) => {
  logger.info(`${emoji} ${message}`, meta);
};

module.exports = { logger };