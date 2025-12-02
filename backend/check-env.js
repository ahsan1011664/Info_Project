/**
 * Helper script to check if .env file is properly configured
 * Run with: node check-env.js
 */

const dotenv = require('dotenv');
const path = require('path');
const fs = require('fs');

console.log('🔍 Checking .env file configuration...\n');

// Check if .env file exists
const envPath = path.join(__dirname, '.env');
const envExists = fs.existsSync(envPath);

if (!envExists) {
  console.error('❌ .env file not found at:', envPath);
  console.log('\n💡 Create a .env file with the following content:');
  console.log(`
MONGODB_URI=mongodb://localhost:27017/secure_messaging
PORT=5000
NODE_ENV=development
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production-12345
CORS_ORIGIN=http://localhost:3000
  `);
  process.exit(1);
}

console.log('✅ .env file found at:', envPath);

// Load environment variables
const result = dotenv.config({ path: envPath });

if (result.error) {
  console.error('❌ Error loading .env file:', result.error.message);
  process.exit(1);
}

// Check required variables
const requiredVars = ['MONGODB_URI', 'JWT_SECRET'];
const optionalVars = ['PORT', 'NODE_ENV', 'CORS_ORIGIN'];

console.log('\n📋 Environment Variables Status:\n');

let allGood = true;

// Check required variables
requiredVars.forEach(varName => {
  if (process.env[varName]) {
    // Mask sensitive values
    const value = varName === 'JWT_SECRET' 
      ? process.env[varName].substring(0, 10) + '...' 
      : process.env[varName];
    console.log(`✅ ${varName}: ${value}`);
  } else {
    console.log(`❌ ${varName}: NOT SET (REQUIRED)`);
    allGood = false;
  }
});

// Check optional variables
optionalVars.forEach(varName => {
  if (process.env[varName]) {
    console.log(`✅ ${varName}: ${process.env[varName]}`);
  } else {
    console.log(`⚠️  ${varName}: NOT SET (using default)`);
  }
});

console.log('\n');

if (allGood) {
  console.log('✅ All required environment variables are set!');
  console.log('💡 You can now start the server with: npm start');
} else {
  console.error('❌ Some required environment variables are missing!');
  console.log('💡 Please update your .env file with the missing variables.');
  process.exit(1);
}

