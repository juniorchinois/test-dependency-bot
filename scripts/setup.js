const fs = require('fs');
const path = require('path');
const readline = require('readline');
const os = require('os');

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
      rl.removeAllListeners('line');
      return;
    }
    privateKey += line + '\n';
    lineCount++;
  });

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

  if (!privateKey.includes('BEGIN RSA PRIVATE KEY') && 
      !privateKey.includes('BEGIN OPENSSH PRIVATE KEY') &&
      !privateKey.includes('BEGIN PRIVATE KEY')) {
    console.log('⚠️ Warning: Your private key doesn\'t look like a valid PEM file.');
    const confirm = await question('Continue anyway? (y/N): ');
    if (confirm.toLowerCase() !== 'y') {
      return await askPrivateKey();
    }
  }

  return privateKey;
}

async function setup() {
  console.log('🚀 Dependency Vulnerability Bot Setup\n');

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
  
  const privateKey = await askPrivateKey();

  if (!appId || !webhookSecret || !privateKey) {
    console.log('\n❌ All fields are required. Setup cancelled.');
    rl.close();
    return;
  }

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
API_TIMEOUT=30000

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
  
  try {
    if (os.platform() !== 'win32') {
      fs.chmodSync(envPath, 0o600);
    }
  } catch (error) {
    console.log('⚠️ Could not set file permissions:', error.message);
  }
  
  console.log('\n✅ .env file created successfully!');

  const dataDir = path.join(__dirname, '../data');
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  const logsDir = path.join(__dirname, '../logs');
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
  }

  console.log('\n🎉 Setup complete!');
  console.log('\n📊 Next steps:');
  console.log('   1. Run `npm install` to install dependencies');
  console.log('   2. Run `npm run dev` to start the bot');
  console.log('   3. Use Smee: `npx smee -u https://smee.io/your-channel -t http://localhost:3000`');
  console.log('   4. For production: `docker-compose up -d`');
  console.log('\n📖 Run `depscan --help` to see CLI usage.\n');
  
  rl.close();
}

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