#!/usr/bin/env node
const { program } = require('commander');
const fs = require('fs');
const path = require('path');
const { scanNPM, scanPip, logger, config } = require('./index');

program
  .version(require('../package.json').version)
  .description('Scan dependencies for vulnerabilities');

program
  .command('scan <file>')
  .description('Scan a dependency file')
  .option('-t, --type <type>', 'Package type (npm|pip)', 'auto')
  .option('-o, --output <format>', 'Output format (json|table)', 'table')
  .action(async (file, options) => {
    try {
      const content = fs.readFileSync(file, 'utf8');
      const type = options.type === 'auto' 
        ? path.basename(file) === 'requirements.txt' ? 'pip' : 'npm'
        : options.type;
      
      let findings;
      if (type === 'npm') {
        findings = await scanNPM(content, () => null, () => {});
      } else if (type === 'pip') {
        findings = await scanPip(content, () => null, () => {});
      } else {
        throw new Error(`Unsupported type: ${type}`);
      }

      if (options.output === 'json') {
        console.log(JSON.stringify(findings, null, 2));
      } else {
        console.log(`\n📦 Found ${findings.length} vulnerable dependencies\n`);
        for (const f of findings) {
          console.log(`❌ ${f.package}@${f.currentVersion}`);
          for (const v of f.vulnerabilities) {
            console.log(`   ${v.id} [${v.severity}] ${v.summary}`);
          }
          if (f.recommendedFix) {
            console.log(`   ✅ Fix: ${f.recommendedFix}`);
          }
          console.log();
        }
      }
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program
  .command('serve')
  .description('Run as GitHub bot server')
  .option('-p, --port <port>', 'Port to listen on', '3000')
  .action(async (options) => {
    const { runBot } = require('./index');
    console.log(`🤖 Starting bot on port ${options.port}`);
    await runBot({ port: parseInt(options.port) });
  });

program
  .command('cache')
  .description('Manage cache')
  .option('-c, --clear', 'Clear cache')
  .option('-s, --stats', 'Show cache stats')
  .action(async (options) => {
    const { getCacheStats, cleanCache } = require('./utils/cache');
    if (options.clear) {
      require('../scripts/clear-cache')();
      console.log('✅ Cache cleared');
    } else if (options.stats) {
      const stats = getCacheStats();
      console.table(stats);
    }
  });

program.parse();