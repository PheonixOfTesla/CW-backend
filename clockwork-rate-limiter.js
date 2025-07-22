const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const { client: redisClient } = require('../config/redis');

// Custom key generator that includes user ID when authenticated
const keyGenerator = (req) => {
  // Use user ID if authenticated, otherwise use IP
  if (req.user && req.user.id) {
    return `user_${req.user.id}`;
  }
  // Use X-Forwarded-For if behind proxy, otherwise use req.ip
  return req.headers['x-forwarded-for'] || req.ip;
};

// Custom skip function to allow certain IPs or users
const skipFunction = (req) => {
  // Skip rate limiting for internal health checks
  if (req.path === '/health') return true;
  
  // Skip for whitelisted IPs (add your monitoring service IPs here)
  const whitelistedIPs = process.env.WHITELISTED_IPS?.split(',') || [];
  const clientIP = req.headers['x-forwarded-for'] || req.ip;
  if (whitelistedIPs.includes(clientIP)) return true;
  
  // Skip for admin users in development
  if (process.env.NODE_ENV === 'development' && req.user?.roles?.includes('admin')) {
    return true;
  }
  
  return false;
};

// Create rate limiter with Redis store
const createLimiter = (options) => {
  const baseOptions = {
    store: new RedisStore({
      client: redisClient,
      prefix: 'rl:',
    }),
    keyGenerator,
    skip: skipFunction,
    standardHeaders: true, // Return rate limit info in headers
    legacyHeaders: false, // Disable X-RateLimit headers
    handler: (req, res) => {
      res.status(429).json({
        error: 'Too many requests',
        message: options.message || 'Please try again later',
        retryAfter: res.getHeader('Retry-After')
      });
    }
  };
  
  return rateLimit({ ...baseOptions, ...options });
};

// Different rate limiters for different endpoints

// General API rate limiter (100 requests per 15 minutes)
const general = createLimiter({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later'
});

// Strict rate limiter for auth endpoints (5 requests per 15 minutes)
const auth = createLimiter({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many authentication attempts, please try again later',
  skipSuccessfulRequests: true // Don't count successful requests
});

// Very strict limiter for sensitive operations (3 requests per hour)
const strict = createLimiter({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: 'Too many attempts, please try again in an hour'
});

// File upload limiter (10 uploads per hour)
const upload = createLimiter({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: 'Upload limit exceeded, please try again later'
});

// API key based rate limiter for external integrations
const apiKey = createLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute
  keyGenerator: (req) => req.headers['x-api-key'] || 'no-api-key',
  skip: (req) => !req.headers['x-api-key'], // Skip if no API key
  message: 'API rate limit exceeded'
});

// Dynamic rate limiter based on user subscription
const dynamic = (req, res, next) => {
  // Determine rate limit based on user's subscription plan
  let maxRequests = 50; // Default for basic plan
  
  if (req.user) {
    const plan = req.user.subscription_plan;
    switch (plan) {
      case 'premium':
        maxRequests = 200;
        break;
      case 'professional':
        maxRequests = 500;
        break;
      case 'enterprise':
        maxRequests = 1000;
        break;
    }
  }
  
  const limiter = createLimiter({
    windowMs: 15 * 60 * 1000,
    max: maxRequests,
    message: `Rate limit exceeded for your subscription plan (${req.user?.subscription_plan || 'basic'})`
  });
  
  limiter(req, res, next);
};

// Websocket connection limiter
const websocket = {
  connections: new Map(),
  maxConnectionsPerUser: 5,
  
  checkLimit: (userId) => {
    const userConnections = websocket.connections.get(userId) || 0;
    if (userConnections >= websocket.maxConnectionsPerUser) {
      return false;
    }
    websocket.connections.set(userId, userConnections + 1);
    return true;
  },
  
  removeConnection: (userId) => {
    const userConnections = websocket.connections.get(userId) || 0;
    if (userConnections > 0) {
      websocket.connections.set(userId, userConnections - 1);
    }
  }
};

// Burst protection - prevent rapid-fire requests
const burst = createLimiter({
  windowMs: 1000, // 1 second
  max: 5, // 5 requests per second max
  message: 'Please slow down your requests'
});

// Custom middleware to track and log rate limit violations
const trackViolations = async (req, res, next) => {
  const originalSend = res.send;
  
  res.send = function(data) {
    if (res.statusCode === 429) {
      // Log rate limit violation
      const violationData = {
        user_id: req.user?.id || null,
        ip_address: req.headers['x-forwarded-for'] || req.ip,
        path: req.path,
        method: req.method,
        user_agent: req.get('user-agent'),
        timestamp: new Date()
      };
      
      // In production, you might want to:
      // 1. Send to monitoring service
      // 2. Store in database for analysis
      // 3. Trigger alerts for repeated violations
      console.warn('Rate limit violation:', violationData);
    }
    
    originalSend.call(this, data);
  };
  
  next();
};

// Helper function to reset rate limit for a specific key
const resetLimit = async (key) => {
  try {
    const redisKey = `rl:${key}`;
    await redisClient.del(redisKey);
    return true;
  } catch (error) {
    console.error('Reset limit error:', error);
    return false;
  }
};

// Helper function to get current rate limit status
const getLimitStatus = async (key) => {
  try {
    const redisKey = `rl:${key}`;
    const count = await redisClient.get(redisKey);
    return {
      key,
      count: parseInt(count) || 0,
      remaining: count ? Math.max(0, 100 - parseInt(count)) : 100 // Assuming 100 is the limit
    };
  } catch (error) {
    console.error('Get limit status error:', error);
    return null;
  }
};

module.exports = {
  general,
  auth,
  strict,
  upload,
  apiKey,
  dynamic,
  websocket,
  burst,
  trackViolations,
  resetLimit,
  getLimitStatus,
  createLimiter
};