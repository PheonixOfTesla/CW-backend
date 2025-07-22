#!/bin/bash

# ClockWork Backend Quick Start Script
# This script sets up your backend development environment

echo "🚀 ClockWork Backend Setup"
echo "========================="

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18+ first."
    exit 1
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Prerequisites checked"
echo ""

# Create project directory
echo "📁 Creating project structure..."
mkdir -p clockwork-backend/{src/{config,controllers,middleware,models,routes,services,utils,socket},migrations,seeds,tests}

# Copy environment variables
echo "📋 Creating environment file..."
cat > clockwork-backend/.env << 'EOF'
# Server
NODE_ENV=development
PORT=3001
API_URL=http://localhost:3001

# Database
DATABASE_URL=postgresql://clockwork:password@localhost:5432/clockwork
REDIS_URL=redis://localhost:6379

# Authentication
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_REFRESH_SECRET=your-refresh-secret-key-change-this-in-production
JWT_EXPIRE=15m
JWT_REFRESH_EXPIRE=7d

# Stripe (Get from https://stripe.com/docs/keys)
STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret

# AWS (Optional for now)
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_REGION=us-east-1
AWS_S3_BUCKET=clockwork-uploads

# Email (Get from https://sendgrid.com)
SENDGRID_API_KEY=your-sendgrid-api-key
EMAIL_FROM=noreply@clockwork.platform

# SMS (Get from https://www.twilio.com)
TWILIO_ACCOUNT_SID=your-twilio-account-sid
TWILIO_AUTH_TOKEN=your-twilio-auth-token
TWILIO_PHONE_NUMBER=+1234567890

# Frontend
FRONTEND_URL=http://localhost:3000
EOF

cd clockwork-backend

# Initialize package.json
echo "📦 Initializing npm project..."
npm init -y

# Install dependencies
echo "📥 Installing dependencies..."
npm install express cors dotenv bcrypt jsonwebtoken pg knex redis socket.io stripe aws-sdk multer multer-s3 nodemailer twilio speakeasy qrcode express-rate-limit helmet compression winston joi sharp

# Install dev dependencies
echo "📥 Installing dev dependencies..."
npm install -D nodemon jest supertest

# Update package.json scripts
echo "📝 Updating package.json scripts..."
node -e "
const pkg = require('./package.json');
pkg.scripts = {
  'start': 'node src/server.js',
  'dev': 'nodemon src/server.js',
  'test': 'jest',
  'migrate': 'knex migrate:latest',
  'migrate:make': 'knex migrate:make',
  'seed': 'knex seed:run',
  'seed:make': 'knex seed:make'
};
require('fs').writeFileSync('./package.json', JSON.stringify(pkg, null, 2));
"

# Create knexfile.js
echo "🔧 Creating Knex configuration..."
cat > knexfile.js << 'EOF'
require('dotenv').config();

module.exports = {
  development: {
    client: 'postgresql',
    connection: process.env.DATABASE_URL,
    migrations: {
      directory: './migrations'
    },
    seeds: {
      directory: './seeds'
    }
  },
  production: {
    client: 'postgresql',
    connection: process.env.DATABASE_URL,
    migrations: {
      directory: './migrations'
    },
    seeds: {
      directory: './seeds'
    }
  }
};
EOF

# Create Docker Compose file
echo "🐳 Creating Docker Compose configuration..."
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_USER: clockwork
      POSTGRES_PASSWORD: password
      POSTGRES_DB: clockwork
    ports:
      - "5432:5432"
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U clockwork"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  maildev:
    image: maildev/maildev
    ports:
      - "1080:1080"
      - "1025:1025"
    environment:
      - MAILDEV_WEB_PORT=1080
      - MAILDEV_SMTP_PORT=1025

volumes:
  postgres-data:
  redis-data:
EOF

# Create .gitignore
echo "📝 Creating .gitignore..."
cat > .gitignore << 'EOF'
node_modules/
.env
.env.local
.env.production
*.log
.DS_Store
coverage/
.nyc_output/
dist/
build/
uploads/
temp/
.vscode/
.idea/
*.swp
*.swo
*~
EOF

# Create basic error handler middleware
echo "🛡️ Creating error handler..."
mkdir -p src/middleware
cat > src/middleware/errorHandler.js << 'EOF'
const errorHandler = (err, req, res, next) => {
  console.error('Error:', err);

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      error: 'Validation Error',
      details: err.message
    });
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      error: 'Invalid token'
    });
  }

  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      error: 'Token expired'
    });
  }

  // Stripe errors
  if (err.type === 'StripeCardError') {
    return res.status(400).json({
      error: err.message
    });
  }

  // Default error
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
};

module.exports = errorHandler;
EOF

# Create Redis configuration
echo "🔴 Creating Redis configuration..."
cat > src/config/redis.js << 'EOF'
const redis = require('redis');

const client = redis.createClient({
  url: process.env.REDIS_URL
});

client.on('error', (err) => {
  console.error('Redis Client Error:', err);
});

client.on('connect', () => {
  console.log('Redis Client Connected');
});

const connectRedis = async () => {
  try {
    await client.connect();
    return client;
  } catch (error) {
    console.error('Failed to connect to Redis:', error);
    throw error;
  }
};

module.exports = {
  client,
  connectRedis,
  get: (key) => client.get(key),
  set: (key, value) => client.set(key, value),
  setex: (key, seconds, value) => client.setEx(key, seconds, value),
  del: (key) => client.del(key),
  exists: (key) => client.exists(key)
};
EOF

# Create Stripe configuration
echo "💳 Creating Stripe configuration..."
cat > src/config/stripe.js << 'EOF'
const Stripe = require('stripe');

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: '2023-10-16'
});

module.exports = stripe;
EOF

# Create validators
echo "✅ Creating validators..."
cat > src/utils/validators.js << 'EOF'
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const validatePassword = (password) => {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*]/.test(password);
  
  const errors = {};
  if (password.length < minLength) errors.length = 'Password must be at least 8 characters';
  if (!hasUpperCase) errors.uppercase = 'Password must contain an uppercase letter';
  if (!hasLowerCase) errors.lowercase = 'Password must contain a lowercase letter';
  if (!hasNumbers) errors.number = 'Password must contain a number';
  if (!hasSpecialChar) errors.special = 'Password must contain a special character';
  
  return {
    isValid: Object.keys(errors).length === 0,
    errors
  };
};

const validatePhone = (phone) => {
  const phoneRegex = /^\+?[\d\s-()]+$/;
  return phoneRegex.test(phone) && phone.replace(/\D/g, '').length >= 10;
};

module.exports = {
  validateEmail,
  validatePassword,
  validatePhone
};
EOF

echo ""
echo "✅ Setup complete!"
echo ""
echo "📚 Next steps:"
echo "1. Start the databases:"
echo "   docker-compose up -d"
echo ""
echo "2. Wait for databases to be ready (about 10 seconds)"
echo ""
echo "3. Copy the complete implementation files:"
echo "   - server.js → src/server.js"
echo "   - database.js → src/config/database.js"
echo "   - 001_initial_schema.js → migrations/"
echo "   - All controller files → src/controllers/"
echo "   - All route files → src/routes/"
echo ""
echo "4. Run database migrations:"
echo "   npm run migrate"
echo ""
echo "5. Start the development server:"
echo "   npm run dev"
echo ""
echo "6. Your backend will be running at http://localhost:3001"
echo ""
echo "📧 Email testing interface: http://localhost:1080"
echo ""
echo "🎉 Happy coding!"