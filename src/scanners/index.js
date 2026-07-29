// src/scanners/index.js
module.exports = {
  scanNPM: require('./npm-scanner').scanNPM,
  scanPip: require('./pip-scanner').scanPip
};