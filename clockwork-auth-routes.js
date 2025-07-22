const router = require('express').Router();
const authController = require('../controllers/authController');
const { authenticate } = require('../middleware/auth');
const { validateRequest } = require('../middleware/validation');
const { validationSchemas } = require('../middleware/validation');
const rateLimiter = require('../middleware/rateLimiter');

// Apply rate limiting to auth routes
const authLimiter = rateLimiter.auth;
const strictLimiter = rateLimiter.strict;

// Public routes (no authentication required)

// User registration
router.post(
  '/signup',
  authLimiter,
  validateRequest(validationSchemas.signup),
  authController.signup
);

// User login
router.post(
  '/login',
  authLimiter,
  validateRequest(validationSchemas.login),
  authController.login
);

// Verify 2FA code
router.post(
  '/verify-2fa',
  strictLimiter,
  validateRequest(validationSchemas.verifyTwoFactor),
  authController.verifyTwoFactor
);

// Refresh access token
router.post(
  '/refresh',
  authLimiter,
  validateRequest(validationSchemas.refreshToken),
  authController.refreshTokens
);

// Request password reset
router.post(
  '/reset-password/request',
  strictLimiter,
  validateRequest(validationSchemas.resetPasswordRequest),
  authController.resetPasswordRequest
);

// Confirm password reset
router.post(
  '/reset-password/confirm',
  strictLimiter,
  validateRequest(validationSchemas.resetPassword),
  authController.resetPassword
);

// Protected routes (authentication required)

// Logout
router.post(
  '/logout',
  authenticate,
  authController.logout
);

// Enable 2FA - Step 1: Get QR code
router.post(
  '/2fa/enable',
  authenticate,
  authController.enableTwoFactor
);

// Enable 2FA - Step 2: Confirm with code
router.post(
  '/2fa/confirm',
  authenticate,
  validateRequest(validationSchemas.enableTwoFactor),
  authController.confirmTwoFactor
);

// Disable 2FA
router.post(
  '/2fa/disable',
  authenticate,
  authController.disableTwoFactor
);

// Get current user info
router.get(
  '/me',
  authenticate,
  async (req, res) => {
    try {
      const user = await db('users')
        .select(
          'id',
          'email',
          'name',
          'phone',
          'roles',
          'subscription_plan',
          'billing_enabled',
          'can_train_clients',
          'two_factor_enabled',
          'profile_picture_url',
          'client_ids',
          'specialist_ids',
          'created_at',
          'updated_at'
        )
        .where({ id: req.user.id })
        .first();
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      res.json({
        ...user,
        roles: JSON.parse(user.roles),
        clientIds: JSON.parse(user.client_ids || '[]'),
        specialistIds: JSON.parse(user.specialist_ids || '[]')
      });
    } catch (error) {
      console.error('Get current user error:', error);
      res.status(500).json({ error: 'Failed to fetch user info' });
    }
  }
);

// Verify JWT token (for frontend session checks)
router.get(
  '/verify',
  authenticate,
  (req, res) => {
    res.json({
      valid: true,
      user: {
        id: req.user.id,
        email: req.user.email,
        name: req.user.name,
        roles: JSON.parse(req.user.roles)
      }
    });
  }
);

// Change password (while logged in)
router.post(
  '/change-password',
  authenticate,
  validateRequest(validationSchemas.changePassword),
  async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;
      const { user } = req;
      
      // Verify current password
      const isValidPassword = await bcrypt.compare(currentPassword, user.password);
      if (!isValidPassword) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }
      
      // Validate new password
      const passwordValidation = validatePassword(newPassword);
      if (!passwordValidation.isValid) {
        return res.status(400).json({ 
          error: 'New password requirements not met', 
          details: passwordValidation.errors 
        });
      }
      
      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      
      // Update password
      await db('users')
        .where({ id: user.id })
        .update({ 
          password: hashedPassword,
          updated_at: new Date()
        });
      
      // Invalidate all existing sessions
      await redis.del(`refresh_${user.id}`);
      
      // Send confirmation email
      await emailService.sendPasswordChangedEmail(user.email, user.name);
      
      // Log audit
      await db('audit_logs').insert({
        user_id: user.id,
        action: 'password_change',
        resource: 'user',
        resource_id: user.id,
        details: 'Password changed while logged in',
        ip_address: req.ip,
        user_agent: req.get('user-agent')
      });
      
      res.json({ 
        message: 'Password changed successfully. Please log in again with your new password.' 
      });
    } catch (error) {
      console.error('Change password error:', error);
      res.status(500).json({ error: 'Failed to change password' });
    }
  }
);

// Get user's security settings
router.get(
  '/security',
  authenticate,
  async (req, res) => {
    try {
      const { user } = req;
      
      // Get recent login activity
      const recentLogins = await db('audit_logs')
        .select('ip_address', 'user_agent', 'timestamp')
        .where({
          user_id: user.id,
          action: 'login'
        })
        .orderBy('timestamp', 'desc')
        .limit(10);
      
      // Get active sessions count (simplified - in production, track sessions properly)
      const activeSessions = await redis.exists(`refresh_${user.id}`) ? 1 : 0;
      
      res.json({
        twoFactorEnabled: user.two_factor_enabled,
        recentLogins: recentLogins.map(login => ({
          ipAddress: login.ip_address,
          userAgent: login.user_agent,
          timestamp: login.timestamp,
          device: parseUserAgent(login.user_agent)
        })),
        activeSessions,
        securityRecommendations: getSecurityRecommendations(user)
      });
    } catch (error) {
      console.error('Get security settings error:', error);
      res.status(500).json({ error: 'Failed to fetch security settings' });
    }
  }
);

// Helper functions
const parseUserAgent = (userAgent) => {
  // Simple user agent parsing - in production, use a library like 'useragent'
  if (!userAgent) return 'Unknown Device';
  
  if (userAgent.includes('Mobile')) return 'Mobile Device';
  if (userAgent.includes('Tablet')) return 'Tablet';
  if (userAgent.includes('Windows')) return 'Windows PC';
  if (userAgent.includes('Mac')) return 'Mac';
  if (userAgent.includes('Linux')) return 'Linux';
  
  return 'Unknown Device';
};

const getSecurityRecommendations = (user) => {
  const recommendations = [];
  
  if (!user.two_factor_enabled) {
    recommendations.push({
      type: 'warning',
      title: 'Enable Two-Factor Authentication',
      description: 'Add an extra layer of security to your account',
      action: 'enable_2fa'
    });
  }
  
  // Add more recommendations based on user's security posture
  
  return recommendations;
};

module.exports = router;