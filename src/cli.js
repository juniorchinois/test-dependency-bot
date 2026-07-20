#!/usr/bin/env node
const { scanNPM } = require('./scanners/npm-scanner');
const fs = require('fs');

async function main() {
  const content = fs.readFileSync('package.json', 'utf8');
  const findings = await scanNPM(content, () => null, () => {});
  console.log(`Found ${findings.length} vulnerabilities`);
}

main();