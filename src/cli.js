#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { program } = require('commander');
const { scanNPM } = require('./scanners/npm-scanner');
const { scanPip } = require('./scanners/pip-scanner');

program
  .name('depscan')
  .description('Scan dependency files for vulnerabilities')
  .version('1.0.5')
  .argument('[file]', 'Path to dependency file', 'package.json')
  .option('-t, --type <type>', 'Package manager type (npm, pip)', 'auto')
  .option('-o, --output <format>', 'Output format (json, table)', 'table')
  .option('--fail-on <severity>', 'Fail on severity (critical, high, medium, low)', 'high')
  .option('--no-cache', 'Disable caching')
  .option('--quiet', 'Suppress output')
  .parse(process.argv);

async function main() {
  const options = program.opts();
  const filePath = program.args[0] || 'package.json';
  
  try {
    if (!fs.existsSync(filePath)) {
      console.error(`❌ File not found: ${filePath}`);
      process.exit(1);
    }
    
    const content = fs.readFileSync(filePath, 'utf8');
    const fileType = options.type === 'auto' ? detectFileType(filePath) : options.type;
    
    if (!options.quiet) {
      console.log(`🔍 Scanning ${filePath} (type: ${fileType})...`);
    }
    
    let findings = [];
    if (fileType === 'npm' || fileType === 'yarn') {
      findings = await scanNPM(content, () => null, () => {});
    } else if (fileType === 'pip' || fileType === 'poetry') {
      findings = await scanPip(content, () => null, () => {});
    } else {
      console.error(`❌ Unsupported package type: ${fileType}`);
      process.exit(1);
    }
    
    const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
    const threshold = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 }[options.failOn?.toLowerCase()] || 3;
    
    const filtered = findings.filter(f => 
      f.vulnerabilities.some(v => (severityOrder[v.severity] || 0) >= threshold)
    );
    
    if (!options.quiet) {
      outputResults(filtered, options.output);
    }
    
    if (filtered.length > 0) {
      console.log(`\n❌ Found ${filtered.length} vulnerabilities above ${options.failOn} severity.`);
      process.exit(1);
    } else {
      console.log(`\n✅ No vulnerabilities found above ${options.failOn} severity.`);
      process.exit(0);
    }
  } catch (error) {
    console.error(`❌ Error: ${error.message}`);
    process.exit(1);
  }
}

function detectFileType(filePath) {
  const name = path.basename(filePath);
  if (['package.json', 'yarn.lock'].includes(name)) return 'npm';
  if (['requirements.txt', 'poetry.lock'].includes(name)) return 'pip';
  return 'npm';
}

function outputResults(findings, format) {
  if (findings.length === 0) {
    console.log('✅ No vulnerabilities found');
    return;
  }
  if (format === 'json') {
    console.log(JSON.stringify(findings, null, 2));
    return;
  }
  console.log('\n📊 Vulnerability Summary:\n');
  for (const f of findings) {
    console.log(`📦 ${f.package}@${f.currentVersion}`);
    for (const v of f.vulnerabilities) {
      console.log(`   🔴 ${v.id} (${v.severity})`);
      console.log(`      ${v.summary || 'No description'}`);
      if (v.fixedVersion) console.log(`      ✅ Fixed in: ${v.fixedVersion}`);
    }
    console.log('');
  }
}

main().catch(error => { console.error('Unhandled error:', error); process.exit(1); });