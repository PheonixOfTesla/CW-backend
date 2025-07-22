const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { db } = require('../config/database');
const redis = require('../config/redis');
const emailService = require('../services/emailService');
const { validateEmail, validatePassword } = require('../utils/validators');

// Generate access and refresh tokens
const generateTokens = (userId) => {
  const accessToken = jwt.sign(
    { id: userId, type: 'access' },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE || '15m' }
  );
  
  const refreshToken = jwt.sign(
    { id: userId, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRE || '7d' }
  );
  
  return { accessToken, refreshToken };
};

// Signup new user
const signup = async (req, res) => {
  const trx = await db.transaction();
  
  try {
    const { email, password, name, phone, roles = ['client'] } = req.body;
    
    // Validate inputs
    if (!validateEmail(email)) {
      await trx.rollback();
      return res.status(400).json({ error: 'Invalid email format' });
    }
    
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      await trx.rollback();
      return res.status(400).json({ 
        error: 'Password requirements not met', 
        details: passwordValidation.errors 
      });
    }
    
    // Check if user exists
    const existingUser = await trx('users').where({ email }).first();
    if (existingUser) {
      await trx.rollback();
      return res.status(409).json({ error: 'Email already registered' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const [user] = await trx('users')
      .insert({
        email: email.toLowerCase(),
        password: hashedPassword,
        name,
        phone,
        roles: JSON.stringify(roles),
        subscription_plan: 'basic',
        client_ids: JSON.stringify([]),
        specialist_ids: JSON.stringify([])
      })
      .returning(['id', 'email', 'name', 'roles', 'created_at']);
    
    // Create default nutrition plan for clients
    if (roles.includes('client')) {
      await trx('nutrition').insert({
        client_id: user.id,
        assigned_by: user.id,
        protein: JSON.stringify({ target: 0, current: 0 }),
        carbs: JSON.stringify({ target: 0, current: 0 }),
        fat: JSON.stringify({ target: 0, current: 0 }),
        calories: JSON.stringify({ target: 0, current: 0 }),
        fiber: JSON.stringify({ target: 0, current: 0 }),
        water: JSON.stringify({ target: 0, current: 0 }),
        meal_plan: JSON.stringify({
          breakfast: '',
          lunch: '',
          dinner: '',
          snacks: ''
        }),
        restrictions: JSON.stringify([]),
        supplements: JSON.stringify([])
      });
    }
    
    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user.id);
    
    // Store refresh token in Redis with user metadata
    await redis.setex(
      `refresh_${user.id}`, 
      7 * 24 * 60 * 60, 
      JSON.stringify({
        token: refreshToken,
        email: user.email,
        roles: user.roles
      })
    );
    
    // Send welcome email
    await emailService.sendWelcomeEmail(email, name);
    
    // Log audit
    await trx('audit_logs').insert({
      user_id: user.id,
      action: 'signup',
      resource: 'user',
      resource_id: user.id,
      details: `User account created with roles: ${roles.join(', ')}`,
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    await trx.commit();
    
    res.status(201).json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        roles: JSON.parse(user.roles),
        createdAt: user.created_at
      },
      accessToken,
      refreshToken,
      message: 'Account created successfully'
    });
  } catch (error) {
    await trx.rollback();
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Failed to create account' });
  }
};

// Login user
const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const user = await db('users')
      .where({ email: email.toLowerCase() })
      .first();
      
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      // Log failed login attempt
      await db('audit_logs').insert({
        user_id: user.id,
        action: 'failed_login',
        resource: 'session',
        resource_id: user.id,
        details: 'Invalid password',
        ip_address: req.ip,
        user_agent: req.get('user-agent')
      });
      
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check if 2FA is enabled
    if (user.two_factor_enabled && user.two_factor_secret) {
      // Generate temporary token for 2FA verification
      const tempToken = jwt.sign(
        { id: user.id, type: '2fa_temp', email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '5m' }
      );
      
      // Store temp token in Redis
      await redis.setex(`2fa_temp_${user.id}`, 300, tempToken);
      
      return res.json({
        requiresTwoFactor: true,
        tempToken,
        message: 'Please enter your 2FA code'
      });
    }
    
    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user.id);
    
    // Store refresh token in Redis
    await redis.setex(
      `refresh_${user.id}`, 
      7 * 24 * 60 * 60, 
      JSON.stringify({
        token: refreshToken,
        email: user.email,
        roles: user.roles
      })
    );
    
    // Update last login
    await db('users')
      .where({ id: user.id })
      .update({ 
        updated_at: new Date(),
        is_online: true,
        last_seen: new Date()
      });
    
    // Log successful login
    await db('audit_logs').insert({
      user_id: user.id,
      action: 'login',
      resource: 'session',
      resource_id: user.id,
      details: 'User logged in successfully',
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        roles: JSON.parse(user.roles),
        subscriptionPlan: user.subscription_plan,
        billingEnabled: user.billing_enabled,
        canTrainClients: user.can_train_clients,
        twoFactorEnabled: user.two_factor_enabled,
        profilePicture: user.profile_picture_url,
        clientIds: JSON.parse(user.client_ids || '[]'),
        specialistIds: JSON.parse(user.specialist_ids || '[]')
      },
      accessToken,
      refreshToken,
      message: 'Login successful'
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
};

// Verify 2FA code
const verifyTwoFactor = async (req, res) => {
  try {
    const { tempToken, code } = req.body;
    
    // Verify temp token
    let decoded;
    try {
      decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    
    if (decoded.type !== '2fa_temp') {
      return res.status(401).json({ error: 'Invalid token type' });
    }
    
    // Check if temp token exists in Redis
    const storedToken = await redis.get(`2fa_temp_${decoded.id}`);
    if (!storedToken || storedToken !== tempToken) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    
    // Get user
    const user = await db('users').where({ id: decoded.id }).first();
    if (!user || !user.two_factor_secret) {
      return res.status(400).json({ error: 'Two-factor authentication not set up' });
    }
    
    // Verify TOTP code
    const verified = speakeasy.totp.verify({
      secret: user.two_factor_secret,
      encoding: 'base32',
      token: code,
      window: 2 // Allow 2 time steps before/after
    });
    
    if (!verified) {
      // Log failed 2FA attempt
      await db('audit_logs').insert({
        user_id: user.id,
        action: 'failed_2fa',
        resource: 'session',
        resource_id: user.id,
        details: 'Invalid 2FA code',
        ip_address: req.ip,
        user_agent: req.get('user-agent')
      });
      
      return res.status(401).json({ error: 'Invalid verification code' });
    }
    
    // Delete temp token
    await redis.del(`2fa_temp_${user.id}`);
    
    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user.id);
    
    // Store refresh token in Redis
    await redis.setex(
      `refresh_${user.id}`, 
      7 * 24 * 60 * 60, 
      JSON.stringify({
        token: refreshToken,
        email: user.email,
        roles: user.roles
      })
    );
    
    // Update user status
    await db('users')
      .where({ id: user.id })
      .update({ 
        updated_at: new Date(),
        is_online: true,
        last_seen: new Date()
      });
    
    // Log successful 2FA
    await db('audit_logs').insert({
      user_id: user.id,
      action: '2fa_success',
      resource: 'session',
      resource_id: user.id,
      details: '2FA verification successful',
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        roles: JSON.parse(user.roles),
        subscriptionPlan: user.subscription_plan,
        billingEnabled: user.billing_enabled,
        canTrainClients: user.can_train_clients,
        twoFactorEnabled: user.two_factor_enabled
      },
      accessToken,
      refreshToken,
      message: '2FA verification successful'
    });
  } catch (error) {
    console.error('2FA verification error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
};

// Logout user
const logout = async (req, res) => {
  try {
    const { user, token } = req;
    
    // Blacklist the current access token
    const decoded = jwt.decode(token);
    const ttl = decoded.exp - Math.floor(Date.now() / 1000);
    if (ttl > 0) {
      await redis.setex(`blacklist_${token}`, ttl, '1');
    }
    
    // Remove refresh token
    await redis.del(`refresh_${user.id}`);
    
    // Update user status
    await db('users')
      .where({ id: user.id })
      .update({ 
        is_online: false,
        last_seen: new Date()
      });
    
    // Log audit
    await db('audit_logs').insert({
      user_id: user.id,
      action: 'logout',
      resource: 'session',
      resource_id: user.id,
      details: 'User logged out',
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
};

// Refresh access token
const refreshTokens = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token required' });
    }
    
    // Verify refresh token
    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch (error) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }
    
    // Check if refresh token exists in Redis
    const storedData = await redis.get(`refresh_${decoded.id}`);
    if (!storedData) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }
    
    const parsedData = JSON.parse(storedData);
    if (parsedData.token !== refreshToken) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }
    
    // Check if user still exists and is active
    const user = await db('users').where({ id: decoded.id }).first();
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    // Generate new tokens
    const tokens = generateTokens(decoded.id);
    
    // Update refresh token in Redis
    await redis.setex(
      `refresh_${decoded.id}`, 
      7 * 24 * 60 * 60, 
      JSON.stringify({
        token: tokens.refreshToken,
        email: user.email,
        roles: user.roles
      })
    );
    
    res.json({
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(401).json({ error: 'Token refresh failed' });
  }
};

// Request password reset
const resetPasswordRequest = async (req, res) => {
  try {
    const { email } = req.body;
    
    const user = await db('users')
      .where({ email: email.toLowerCase() })
      .first();
      
    if (!user) {
      // Don't reveal if user exists - security best practice
      return res.json({ 
        message: 'If an account exists with this email, you will receive a password reset link.' 
      });
    }
    
    // Generate reset token
    const resetToken = jwt.sign(
      { id: user.id, type: 'password_reset', email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    // Store in Redis with 1 hour expiry
    await redis.setex(`reset_${resetToken}`, 3600, user.id);
    
    // Send reset email
    await emailService.sendPasswordResetEmail(user.email, user.name, resetToken);
    
    // Log password reset request
    await db('audit_logs').insert({
      user_id: user.id,
      action: 'password_reset_request',
      resource: 'user',
      resource_id: user.id,
      details: 'Password reset requested',
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.json({ 
      message: 'If an account exists with this email, you will receive a password reset link.' 
    });
  } catch (error) {
    console.error('Password reset request error:', error);
    res.status(500).json({ error: 'Failed to process request' });
  }
};

// Reset password with token
const resetPassword = async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    
    if (decoded.type !== 'password_reset') {
      return res.status(400).json({ error: 'Invalid token type' });
    }
    
    // Check if token exists in Redis
    const userId = await redis.get(`reset_${token}`);
    if (!userId || userId !== decoded.id) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    
    // Validate new password
    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.isValid) {
      return res.status(400).json({ 
        error: 'Password requirements not met', 
        details: passwordValidation.errors 
      });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    // Update password
    await db('users')
      .where({ id: userId })
      .update({ 
        password: hashedPassword,
        updated_at: new Date()
      });
    
    // Delete reset token
    await redis.del(`reset_${token}`);
    
    // Invalidate all existing refresh tokens for this user
    await redis.del(`refresh_${userId}`);
    
    // Send confirmation email
    const user = await db('users').where({ id: userId }).first();
    await emailService.sendPasswordChangedEmail(user.email, user.name);
    
    // Log password reset
    await db('audit_logs').insert({
      user_id: userId,
      action: 'password_reset',
      resource: 'user',
      resource_id: userId,
      details: 'Password reset successfully',
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.json({ 
      message: 'Password reset successfully. Please login with your new password.' 
    });
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(400).json({ error: 'Failed to reset password' });
  }
};

// Enable two-factor authentication
const enableTwoFactor = async (req, res) => {
  try {
    const { user } = req;
    
    // Check if already enabled
    if (user.two_factor_enabled) {
      return res.status(400).json({ error: 'Two-factor authentication is already enabled' });
    }
    
    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `ClockWork (${user.email})`,
      issuer: 'ClockWork Platform',
      length: 32
    });
    
    // Store secret temporarily in Redis (10 minutes to confirm)
    await redis.setex(`2fa_setup_${user.id}`, 600, secret.base32);
    
    // Generate QR code
    const qrCode = await QRCode.toDataURL(secret.otpauth_url);
    
    res.json({
      secret: secret.base32,
      qrCode,
      manualEntry: secret.otpauth_url,
      message: 'Scan the QR code with your authenticator app and confirm with a code'
    });
  } catch (error) {
    console.error('2FA setup error:', error);
    res.status(500).json({ error: 'Failed to set up two-factor authentication' });
  }
};

// Confirm two-factor authentication setup
const confirmTwoFactor = async (req, res) => {
  try {
    const { user } = req;
    const { code } = req.body;
    
    // Get temporary secret
    const secret = await redis.get(`2fa_setup_${user.id}`);
    if (!secret) {
      return res.status(400).json({ error: 'No pending 2FA setup found. Please start again.' });
    }
    
    // Verify code
    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token: code,
      window: 2
    });
    
    if (!verified) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }
    
    // Save secret to database
    await db('users')
      .where({ id: user.id })
      .update({
        two_factor_secret: secret,
        two_factor_enabled: true,
        updated_at: new Date()
      });
    
    // Clean up temporary secret
    await redis.del(`2fa_setup_${user.id}`);
    
    // Generate backup codes
    const backupCodes = Array.from({ length: 8 }, () => 
      Math.random().toString(36).substring(2, 10).toUpperCase()
    );
    
    // Store backup codes (hashed) in Redis
    const hashedBackupCodes = await Promise.all(
      backupCodes.map(code => bcrypt.hash(code, 10))
    );
    await redis.setex(
      `2fa_backup_${user.id}`, 
      365 * 24 * 60 * 60, // 1 year
      JSON.stringify(hashedBackupCodes)
    );
    
    // Log 2FA enablement
    await db('audit_logs').insert({
      user_id: user.id,
      action: '2fa_enabled',
      resource: 'user',
      resource_id: user.id,
      details: 'Two-factor authentication enabled',
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.json({ 
      message: 'Two-factor authentication enabled successfully',
      backupCodes,
      warning: 'Save these backup codes in a secure place. Each code can only be used once.'
    });
  } catch (error) {
    console.error('2FA confirmation error:', error);
    res.status(500).json({ error: 'Failed to confirm two-factor authentication' });
  }
};

// Disable two-factor authentication
const disableTwoFactor = async (req, res) => {
  try {
    const { user } = req;
    const { password } = req.body;
    
    // Verify password before disabling 2FA
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid password' });
    }
    
    // Disable 2FA
    await db('users')
      .where({ id: user.id })
      .update({
        two_factor_enabled: false,
        two_factor_secret: null,
        updated_at: new Date()
      });
    
    // Remove backup codes
    await redis.del(`2fa_backup_${user.id}`);
    
    // Log 2FA disablement
    await db('audit_logs').insert({
      user_id: user.id,
      action: '2fa_disabled',
      resource: 'user',
      resource_id: user.id,
      details: 'Two-factor authentication disabled',
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    res.json({ message: 'Two-factor authentication disabled successfully' });
  } catch (error) {
    console.error('2FA disable error:', error);
    res.status(500).json({ error: 'Failed to disable two-factor authentication' });
  }
};

module.exports = {
  signup,
  login,
  verifyTwoFactor,
  logout,
  refreshTokens,
  resetPasswordRequest,
  resetPassword,
  enableTwoFactor,
  confirmTwoFactor,
  disableTwoFactor
};