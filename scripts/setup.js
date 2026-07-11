const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { logger } = require('../src/utils/logger');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function question(query) {
  return new Promise(resolve => {
    rl.question(query, resolve);
  });
}

async function setup() {
  console.log('🚀 Dependency Vulnerability Bot Setup\n');
  console.log('This script will help you configure the bot.\n');

  // Check for .env file
  const envPath = path.join(__dirname, '../.env');
  let envExists = fs.existsSync(envPath);
  
  if (envExists) {
    const overwrite = await question('⚠️ .env file already exists. Overwrite? (y/N): ');
    if (overwrite.toLowerCase() !== 'y') {
      console.log('Setup cancelled.');
      rl.close();
      return;
    }
  }

  console.log('\n📝 Please enter your GitHub App configuration:\n');

  const appId = await question('APP_ID (from GitHub App settings): ');
  const webhookSecret = await question('WEBHOOK_SECRET (from GitHub App settings): ');
  
  console.log('\n📋 Private key (paste the contents of your .pem file, press Ctrl+D when done):');
  let privateKey = '';
  
  rl.on('line', (line) => {
    privateKey += line + '\n';
  });

  rl.on('close', async () => {
    // Create .env file
    const envContent = `# GitHub App Configuration
APP_ID=${appId}
PRIVATE_KEY="${privateKey.trim()}"
WEBHOOK_SECRET=${webhookSecret}

# Bot Configuration
SEVERITY_THRESHOLD=HIGH
COMMENT_ONLY_ON_NEW=false
IGNORED_PACKAGES=
SKIP_FORKS=true
LOG_LEVEL=info

# OSV API Configuration
OSV_API_URL=https://api.osv.dev/v1/query

# Cache Configuration
CACHE_TTL=86400
`;

    fs.writeFileSync(envPath, envContent);
    console.log('\n✅ .env file created successfully!');

    // Create data directory
    const dataDir = path.join(__dirname, '../data');
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
      console.log('📁 Data directory created');
    }

    // Create logs directory
    const logDir = path.join(__dirname, '../logs');
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
      console.log('📁 Logs directory created');
    }

    console.log('\n🎉 Setup complete!');
    console.log('\nNext steps:');
    console.log('1. Run `npm install` to install dependencies');
    console.log('2. Run `npm run dev` to start the bot in development mode');
    console.log('3. Use Smee to test webhooks: `npx smee -u https://smee.io/your-channel -t http://localhost:3000`');
    console.log('\nFor more information, check the README.md file.');
  });
}

// Handle Ctrl+C
process.on('SIGINT', () => {
  console.log('\n\nSetup cancelled.');
  rl.close();
  process.exit(0);
});

if (require.main === module) {
  setup();
}