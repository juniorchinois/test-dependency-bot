const fs = require('fs');
const path = require('path');
const readline = require('readline');
const crypto = require('crypto');

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
  
  // Store the line handler so we can remove it later
  const lineHandler = (line) => {
    privateKey += line + '\n';
  };
  
  rl.on('line', lineHandler);

  // Need to handle this differently since we're using readline
  // We'll collect the private key with a temporary approach
  console.log('(Paste your private key and press Enter twice when done)');
  
  // Create .env file after collecting private key
  const envContent = `# GitHub App Configuration
APP_ID=${appId}
PRIVATE_KEY="${privateKey.trim().replace(/"/g, '\\"')}"
WEBHOOK_SECRET=${webhookSecret}

# Bot Configuration
SEVERITY_THRESHOLD=HIGH
COMMENT_ONLY_ON_NEW=false
IGNORED_PACKAGES=
SKIP_FORKS=true
LOG_LEVEL=info

# OSV API Configuration - Single query endpoint (consistent with code)
OSV_API_URL=https://api.osv.dev/v1/query

# Cache Configuration - Uses temp directory by default
CACHE_TTL=86400

# Ecosystems
ENABLE_NPM=true
ENABLE_PIP=true
ENABLE_YARN=false
ENABLE_POETRY=false
`;

  fs.writeFileSync(envPath, envContent);
  console.log('\n✅ .env file created successfully!');

  console.log('\n🎉 Setup complete!');
  console.log('\nNext steps:');
  console.log('1. Run `npm install` to install dependencies');
  console.log('2. Run `npm run dev` to start the bot in development mode');
  console.log('3. Use Smee to test webhooks: `npx smee -u https://smee.io/your-channel -t http://localhost:3000`');
  console.log('\nFor more information, check the README.md file.');
  
  rl.close();
}

// Handle Ctrl+C
process.on('SIGINT', () => {
  console.log('\n\nSetup cancelled.');
  rl.close();
  process.exit(0);
});

if (require.main === module) {
  setup().catch(console.error);
}