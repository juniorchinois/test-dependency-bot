#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { program } = require('commander');
const { scanNPM } = require('./scanners/npm-scanner');
const { scanPip } = require('./scanners/pip-scanner');

// No-op cache for CLI mode (avoid cache side effects)
const noopCache = {
  getCached: () => null,
  setCached: () => {}
};

program
  .name('depscan')
  .description('Scan dependency files for vulnerabilities')
  .version('1.0.3')
  .option('-f, --file <path>', 'Path to dependency file (package.json, requirements.txt, etc.)', 'package.json')
  .option('-t, --type <type>', 'Package manager type (npm, pip)', 'auto')
  .option('-o, --output <format>', 'Output format (json, table)', 'table')
  .option('--fail-on <severity>', 'Fail with non-zero exit code if vulnerabilities above this severity (critical, high, medium, low)', 'high')
  .option('--no-cache', 'Disable caching')
  .option('--quiet', 'Suppress output')
  .parse(process.argv);

async function main() {
  const options = program.opts();
  const filePath = options.file;
  
  try {
    // Check if file exists
    if (!fs.existsSync(filePath)) {
      console.error(`❌ File not found: ${filePath}`);
      process.exit(1);
    }
    
    // Read and parse the file
    const content = fs.readFileSync(filePath, 'utf8');
    let findings = [];
    
    // Auto-detect or use specified type
    let fileType = options.type;
    if (fileType === 'auto') {
      fileType = detectFileType(filePath);
    }
    
    if (!options.quiet) {
      console.log(`🔍 Scanning ${filePath} (type: ${fileType})...`);
    }
    
    if (fileType === 'npm' || fileType === 'yarn') {
      findings = await scanNPM(content, noopCache.getCached, noopCache.setCached);
    } else if (fileType === 'pip' || fileType === 'poetry') {
      findings = await scanPip(content, noopCache.getCached, noopCache.setCached);
    } else {
      console.error(`❌ Unsupported package type: ${fileType}`);
      process.exit(1);
    }
    
    // Filter by severity threshold
    const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
    const thresholdMap = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 };
    const thresholdLevel = thresholdMap[options.failOn.toLowerCase()] || 3;
    
    const filteredFindings = findings.filter(finding => {
      return finding.vulnerabilities.some(v => {
        const level = severityOrder[v.severity] || 0;
        return level >= thresholdLevel;
      });
    });
    
    // Output results
    if (!options.quiet) {
      outputResults(filteredFindings, options.output);
    }
    
    // Exit with appropriate code
    if (filteredFindings.length > 0) {
      console.log(`\n❌ Found ${filteredFindings.length} vulnerabilities above ${options.failOn} severity.`);
      process.exit(1);
    } else {
      console.log(`\n✅ No vulnerabilities found above ${options.failOn} severity.`);
      process.exit(0);
    }
    
  } catch (error) {
    console.error(`❌ Error: ${error.message}`);
    if (error.stack && !options.quiet) {
      console.error(error.stack);
    }
    process.exit(1);
  }
}

function detectFileType(filePath) {
  const filename = path.basename(filePath);
  switch (filename) {
    case 'package.json':
    case 'yarn.lock':
      return 'npm';
    case 'requirements.txt':
    case 'poetry.lock':
      return 'pip';
    default:
      const ext = path.extname(filePath);
      if (ext === '.json') return 'npm';
      if (ext === '.txt' || ext === '.lock') return 'pip';
      return 'npm';
  }
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
  
  // Table format (default)
  console.log('\n📊 Vulnerability Summary:\n');
  console.log('┌─────────────────────────┬─────────────────┬────────────┬──────────────────────────┐');
  console.log('│ Package                  │ Current Version │ Severity   │ Vulnerability ID          │');
  console.log('├─────────────────────────┼─────────────────┼────────────┼──────────────────────────┤');
  
  for (const finding of findings) {
    const pkgName = finding.package.padEnd(24).slice(0, 24);
    const version = finding.currentVersion.padEnd(15).slice(0, 15);
    const severity = finding.vulnerabilities[0]?.severity.padEnd(10).slice(0, 10) || 'UNKNOWN';
    const vulnId = finding.vulnerabilities[0]?.id.padEnd(24).slice(0, 24) || 'N/A';
    console.log(`│ ${pkgName}│ ${version}│ ${severity}│ ${vulnId}│`);
  }
  
  console.log('└─────────────────────────┴─────────────────┴────────────┴──────────────────────────┘');
  
  // Add details
  console.log('\n📋 Details:');
  for (const finding of findings) {
    console.log(`\n📦 ${finding.package}@${finding.currentVersion}`);
    console.log(`   Fix version: ${finding.recommendedFix || 'No fix available'}`);
    for (const vuln of finding.vulnerabilities) {
      console.log(`   🔴 ${vuln.id} (${vuln.severity})`);
      console.log(`      ${vuln.summary || 'No summary available'}`);
      if (vuln.references && vuln.references.length > 0) {
        console.log(`      ${vuln.references[0]}`);
      }
    }
  }
}

// Run the CLI
main().catch(error => {
  console.error('Unhandled error:', error);
  process.exit(1);
});