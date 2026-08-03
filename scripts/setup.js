// const fs = require('fs');
// const path = require('path');
// const readline = require('readline');
// const crypto = require('crypto');

// const rl = readline.createInterface({
//   input: process.stdin,
//   output: process.stdout
// });

// function question(query) {
//   return new Promise(resolve => {
//     rl.question(query, resolve);
//   });
// }

// async function setup() {
//   console.log('🚀 Dependency Vulnerability Bot Setup\n');
//   console.log('This script will help you configure the bot.\n');

//   // Check for .env file
//   const envPath = path.join(__dirname, '../.env');
//   let envExists = fs.existsSync(envPath);
  
//   if (envExists) {
//     const overwrite = await question('⚠️ .env file already exists. Overwrite? (y/N): ');
//     if (overwrite.toLowerCase() !== 'y') {
//       console.log('Setup cancelled.');
//       rl.close();
//       return;
//     }
//   }

//   console.log('\n📝 Please enter your GitHub App configuration:\n');

//   const appId = await question('APP_ID (from GitHub App settings): ');
//   const webhookSecret = await question('WEBHOOK_SECRET (from GitHub App settings): ');
  
//   console.log('\n📋 Private key (paste the contents of your .pem file, press Ctrl+D when done):');
//   let privateKey = '';
  
//   // Store the line handler so we can remove it later
//   const lineHandler = (line) => {
//     privateKey += line + '\n';
//   };
  
//   rl.on('line', lineHandler);

//   // Need to handle this differently since we're using readline
//   // We'll collect the private key with a temporary approach
//   console.log('(Paste your private key and press Enter twice when done)');
  
//   // Create .env file after collecting private key
//   const envContent = `# GitHub App Configuration
// APP_ID=${appId}
// PRIVATE_KEY="${privateKey.trim().replace(/"/g, '\\"')}"
// WEBHOOK_SECRET=${webhookSecret}

// # Bot Configuration
// SEVERITY_THRESHOLD=HIGH
// COMMENT_ONLY_ON_NEW=false
// IGNORED_PACKAGES=
// SKIP_FORKS=true
// LOG_LEVEL=info

// # OSV API Configuration - Single query endpoint (consistent with code)
// OSV_API_URL=https://api.osv.dev/v1/query

// # Cache Configuration - Uses temp directory by default
// CACHE_TTL=86400

// # Ecosystems
// ENABLE_NPM=true
// ENABLE_PIP=true
// ENABLE_YARN=false
// ENABLE_POETRY=false
// `;

//   fs.writeFileSync(envPath, envContent);
//   console.log('\n✅ .env file created successfully!');

//   console.log('\n🎉 Setup complete!');
//   console.log('\nNext steps:');
//   console.log('1. Run `npm install` to install dependencies');
//   console.log('2. Run `npm run dev` to start the bot in development mode');
//   console.log('3. Use Smee to test webhooks: `npx smee -u https://smee.io/your-channel -t http://localhost:3000`');
//   console.log('\nFor more information, check the README.md file.');
  
//   rl.close();
// }

// // Handle Ctrl+C
// process.on('SIGINT', () => {
//   console.log('\n\nSetup cancelled.');
//   rl.close();
//   process.exit(0);
// });

// if (require.main === module) {
//   setup().catch(console.error);
// }

// scripts/setup.js - IMPROVED
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const crypto = require('crypto');
const os = require('os');
const { promisify } = require('util');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function question(query) {
  return new Promise(resolve => {
    rl.question(query, resolve);
  });
}

async function askPrivateKey() {
  console.log('\n📋 Private Key (paste the contents of your .pem file):');
  console.log('   Enter your private key, then type "END" on a new line when done.\n');
  
  let privateKey = '';
  let lineCount = 0;
  
  rl.on('line', (line) => {
    if (line.trim() === 'END') {
      // User finished entering key
      rl.removeAllListeners('line');
      return;
    }
    privateKey += line + '\n';
    lineCount++;
  });

  // Wait for the user to type "END"
  await new Promise((resolve) => {
    const checkEnd = (line) => {
      if (line.trim() === 'END') {
        rl.removeListener('line', checkEnd);
        resolve();
      }
    };
    rl.on('line', checkEnd);
  });

  if (lineCount === 0) {
    console.log('⚠️ No private key entered. Please try again.');
    return await askPrivateKey();
  }

  // Validate that it looks like a proper private key
  if (!privateKey.includes('BEGIN RSA PRIVATE KEY') && 
      !privateKey.includes('BEGIN OPENSSH PRIVATE KEY') &&
      !privateKey.includes('BEGIN PRIVATE KEY')) {
    console.log('⚠️ Warning: Your private key doesn\'t look like a valid PEM file.');
    console.log('   Make sure you\'ve copied the correct key from GitHub App settings.\n');
    const confirm = await question('Continue anyway? (y/N): ');
    if (confirm.toLowerCase() !== 'y') {
      return await askPrivateKey();
    }
  }

  return privateKey;
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
  
  // Get private key with improved method
  const privateKey = await askPrivateKey();

  // Validate inputs
  if (!appId || !webhookSecret || !privateKey) {
    console.log('\n❌ All fields are required. Setup cancelled.');
    rl.close();
    return;
  }

  // Create .env file
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

# OSV API Configuration
OSV_API_URL=https://api.osv.dev/v1/query

# Cache Configuration
CACHE_TTL=86400
MAX_DEPENDENCIES=100
API_TIMEOUT=15000
MAX_RETRIES=3
RETRY_DELAY=1000

# Ecosystems
ENABLE_NPM=true
ENABLE_PIP=true
ENABLE_YARN=false
ENABLE_POETRY=false

# Comment Management
ALWAYS_CREATE_NEW_COMMENT=false
REMOVE_OLD_COMMENTS=false
`;

  fs.writeFileSync(envPath, envContent);
  
  // Set secure permissions (readable only by owner)
  try {
    if (os.platform() !== 'win32') {
      fs.chmodSync(envPath, 0o600);
    }
  } catch (error) {
    console.log('⚠️ Could not set file permissions:', error.message);
  }
  
  console.log('\n✅ .env file created successfully!');
  console.log('   (File permissions set to read-only for the owner)');

  // Create data directory
  const dataDir = path.join(__dirname, '../data');
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  // Create logs directory
  const logsDir = path.join(__dirname, '../logs');
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
  }

  console.log('\n🎉 Setup complete!');
  console.log('\n📊 Next steps:');
  console.log('   1. Run `npm install` to install dependencies');
  console.log('   2. Run `npm run dev` to start the bot in development mode');
  console.log('   3. Use Smee to test webhooks:');
  console.log('      `npx smee -u https://smee.io/your-channel -t http://localhost:3000`');
  console.log('   4. For production deployment:');
  console.log('      `docker-compose up -d`');
  console.log('\n📖 For more information, check the README.md file.');
  console.log('   Run `depscan --help` to see CLI usage.\n');
  
  rl.close();
}

// Handle Ctrl+C
process.on('SIGINT', () => {
  console.log('\n\nSetup cancelled.');
  rl.close();
  process.exit(0);
});

if (require.main === module) {
  setup().catch((error) => {
    console.error('Setup error:', error);
    process.exit(1);
  });
}