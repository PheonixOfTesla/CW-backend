const sgMail = require('@sendgrid/mail');
const { db } = require('../config/database');

// Initialize SendGrid
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Email templates
const emailTemplates = {
  welcome: {
    subject: 'Welcome to ClockWork! 🎉',
    template: (name) => `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: linear-gradient(135deg, #0f172a 0%, #3b82f6 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
    .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
    .button { display: inline-block; background: #3b82f6; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin-top: 20px; }
    .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
    .feature { margin: 15px 0; padding-left: 25px; }
    .logo { font-size: 32px; font-weight: bold; letter-spacing: 2px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="logo">CLOCKWORK</div>
      <p style="margin: 10px 0 0 0; opacity: 0.9;">Universal Business Platform</p>
    </div>
    <div class="content">
      <h2>Welcome aboard, ${name}! 🚀</h2>
      <p>We're thrilled to have you join the ClockWork community. Your journey to better business management starts now!</p>
      
      <h3>Here's what you can do with ClockWork:</h3>
      <div class="feature">✅ Track client progress with detailed measurements</div>
      <div class="feature">📊 Visualize data with beautiful charts and reports</div>
      <div class="feature">💪 Create and manage custom workout plans</div>
      <div class="feature">🥗 Design personalized nutrition programs</div>
      <div class="feature">💬 Communicate seamlessly with real-time chat</div>
      <div class="feature">💳 Handle billing and subscriptions effortlessly</div>
      
      <center>
        <a href="${process.env.FRONTEND_URL}/login" class="button">Get Started</a>
      </center>
      
      <h3>Need help getting started?</h3>
      <p>Check out our <a href="${process.env.FRONTEND_URL}/help">help center</a> or reply to this email - we're here to help!</p>
    </div>
    <div class="footer">
      <p>© ${new Date().getFullYear()} ClockWork Platform. All rights reserved.</p>
      <p>You're receiving this email because you signed up for ClockWork.</p>
    </div>
  </div>
</body>
</html>
    `
  },
  
  passwordReset: {
    subject: 'Reset Your ClockWork Password',
    template: (name, resetLink) => `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: #0f172a; color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
    .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
    .button { display: inline-block; background: #ef4444; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
    .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
    .warning { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Password Reset Request</h1>
    </div>
    <div class="content">
      <h2>Hi ${name},</h2>
      <p>We received a request to reset your ClockWork password. Click the button below to create a new password:</p>
      
      <center>
        <a href="${resetLink}" class="button">Reset Password</a>
      </center>
      
      <p><small>Or copy and paste this link into your browser:</small><br>
      <small>${resetLink}</small></p>
      
      <div class="warning">
        <strong>⚠️ Important:</strong> This link will expire in 1 hour for security reasons. If you didn't request this password reset, please ignore this email or contact support if you have concerns.
      </div>
      
      <p>For security reasons, we recommend:</p>
      <ul>
        <li>Using a strong, unique password</li>
        <li>Enabling two-factor authentication</li>
        <li>Not sharing your password with anyone</li>
      </ul>
    </div>
    <div class="footer">
      <p>© ${new Date().getFullYear()} ClockWork Platform. All rights reserved.</p>
      <p>This is an automated security email. Please do not reply.</p>
    </div>
  </div>
</body>
</html>
    `
  },
  
  passwordChanged: {
    subject: 'Your ClockWork Password Has Been Changed',
    template: (name) => `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: #10b981; color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
    .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
    .alert { background: #fee; border-left: 4px solid #ef4444; padding: 15px; margin: 20px 0; }
    .button { display: inline-block; background: #3b82f6; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin-top: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Password Successfully Changed</h1>
    </div>
    <div class="content">
      <h2>Hi ${name},</h2>
      <p>This email confirms that your ClockWork password has been successfully changed.</p>
      
      <p><strong>When:</strong> ${new Date().toLocaleString()}</p>
      
      <div class="alert">
        <strong>🚨 Wasn't you?</strong> If you didn't make this change, your account may be compromised. Please contact our support team immediately.
      </div>
      
      <p>To keep your account secure:</p>
      <ul>
        <li>Enable two-factor authentication if you haven't already</li>
        <li>Review your recent account activity</li>
        <li>Update your password on any other services where you used the same one</li>
      </ul>
      
      <center>
        <a href="${process.env.FRONTEND_URL}/login" class="button">Login to ClockWork</a>
      </center>
    </div>
    <div class="footer">
      <p>© ${new Date().getFullYear()} ClockWork Platform. All rights reserved.</p>
    </div>
  </div>
</body>
</html>
    `
  },
  
  workoutAssigned: {
    subject: 'New Workout Plan Ready! 💪',
    template: (clientName, specialistName, workoutName) => `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: linear-gradient(135deg, #3b82f6 0%, #60a5fa 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
    .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
    .workout-box { background: white; border: 2px solid #3b82f6; border-radius: 8px; padding: 20px; margin: 20px 0; }
    .button { display: inline-block; background: #3b82f6; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin-top: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>💪 New Workout Available!</h1>
    </div>
    <div class="content">
      <h2>Hi ${clientName}!</h2>
      <p>Great news! ${specialistName} has created a new workout plan for you.</p>
      
      <div class="workout-box">
        <h3 style="margin-top: 0;">${workoutName}</h3>
        <p>Your personalized workout is ready to help you achieve your fitness goals!</p>
      </div>
      
      <p>Log in to ClockWork to:</p>
      <ul>
        <li>View your complete workout plan</li>
        <li>Track your progress</li>
        <li>Record your performance</li>
        <li>Chat with ${specialistName} about your workout</li>
      </ul>
      
      <center>
        <a href="${process.env.FRONTEND_URL}/workouts" class="button">View Workout</a>
      </center>
      
      <p style="margin-top: 30px;"><em>Remember: Consistency is key! Let's crush those goals together! 🎯</em></p>
    </div>
    <div class="footer">
      <p>© ${new Date().getFullYear()} ClockWork Platform. All rights reserved.</p>
    </div>
  </div>
</body>
</html>
    `
  },
  
  invoiceCreated: {
    subject: 'New Invoice from ClockWork',
    template: (clientName, invoiceDetails) => `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: #0f172a; color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
    .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
    .invoice-box { background: white; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 20px 0; }
    .invoice-header { display: flex; justify-content: space-between; margin-bottom: 20px; }
    .invoice-items { margin: 20px 0; }
    .invoice-item { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #eee; }
    .total { display: flex; justify-content: space-between; font-weight: bold; font-size: 18px; margin-top: 20px; padding-top: 20px; border-top: 2px solid #333; }
    .button { display: inline-block; background: #3b82f6; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin-top: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Invoice #${invoiceDetails.id}</h1>
    </div>
    <div class="content">
      <h2>Hi ${clientName},</h2>
      <p>A new invoice has been created for your account:</p>
      
      <div class="invoice-box">
        <div class="invoice-header">
          <div>
            <strong>Invoice Date:</strong> ${new Date(invoiceDetails.date).toLocaleDateString()}<br>
            <strong>Due Date:</strong> ${new Date(invoiceDetails.dueDate).toLocaleDateString()}
          </div>
          <div style="text-align: right;">
            <strong>Status:</strong> ${invoiceDetails.status.toUpperCase()}
          </div>
        </div>
        
        <div class="invoice-items">
          ${invoiceDetails.items.map(item => `
            <div class="invoice-item">
              <span>${item.description}</span>
              <span>$${item.amount.toFixed(2)}</span>
            </div>
          `).join('')}
        </div>
        
        <div style="text-align: right; margin-top: 20px;">
          <div style="margin-bottom: 5px;">Subtotal: $${invoiceDetails.amount.toFixed(2)}</div>
          <div style="margin-bottom: 5px;">Tax: $${invoiceDetails.tax.toFixed(2)}</div>
          <div class="total">
            <span>Total Due:</span>
            <span>$${invoiceDetails.total.toFixed(2)}</span>
          </div>
        </div>
      </div>
      
      <center>
        <a href="${process.env.FRONTEND_URL}/billing" class="button">View & Pay Invoice</a>
      </center>
      
      <p style="margin-top: 30px; font-size: 14px; color: #666;">
        Questions about this invoice? Reply to this email or contact your specialist through ClockWork.
      </p>
    </div>
    <div class="footer">
      <p>© ${new Date().getFullYear()} ClockWork Platform. All rights reserved.</p>
    </div>
  </div>
</body>
</html>
    `
  },
  
  appointmentReminder: {
    subject: 'Reminder: Upcoming Session Tomorrow',
    template: (clientName, sessionDetails) => `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: #fbbf24; color: #0f172a; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
    .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
    .session-box { background: white; border: 2px solid #fbbf24; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: center; }
    .button { display: inline-block; background: #3b82f6; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin-top: 20px; }
    .details { background: #e0f2fe; padding: 15px; border-radius: 8px; margin: 20px 0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>📅 Session Reminder</h1>
    </div>
    <div class="content">
      <h2>Hi ${clientName}!</h2>
      <p>This is a friendly reminder about your upcoming session:</p>
      
      <div class="session-box">
        <h3 style="margin: 0; color: #3b82f6;">${sessionDetails.type}</h3>
        <p style="font-size: 24px; margin: 10px 0;">
          📅 ${new Date(sessionDetails.date).toLocaleDateString()}<br>
          ⏰ ${sessionDetails.time}
        </p>
        <p style="margin: 5px 0;">
          <strong>Duration:</strong> ${sessionDetails.duration} minutes<br>
          <strong>With:</strong> ${sessionDetails.trainerName}
        </p>
      </div>
      
      <div class="details">
        <strong>📍 Location:</strong> ${sessionDetails.location || 'To be confirmed'}<br>
        ${sessionDetails.zoomLink ? `<strong>💻 Zoom Link:</strong> <a href="${sessionDetails.zoomLink}">Join Session</a><br>` : ''}
        ${sessionDetails.notes ? `<strong>📝 Notes:</strong> ${sessionDetails.notes}` : ''}
      </div>
      
      <p>Need to reschedule? Login to ClockWork or contact ${sessionDetails.trainerName} as soon as possible.</p>
      
      <center>
        <a href="${process.env.FRONTEND_URL}/training" class="button">View Session Details</a>
      </center>
    </div>
    <div class="footer">
      <p>© ${new Date().getFullYear()} ClockWork Platform. All rights reserved.</p>
    </div>
  </div>
</body>
</html>
    `
  }
};

// Email service class
class EmailService {
  constructor() {
    this.from = process.env.EMAIL_FROM || 'noreply@clockwork.platform';
    this.isDevelopment = process.env.NODE_ENV === 'development';
  }
  
  // Send email
  async send(to, subject, html, options = {}) {
    try {
      const msg = {
        to,
        from: this.from,
        subject,
        html,
        ...options
      };
      
      if (this.isDevelopment) {
        // In development, log emails instead of sending
        console.log('📧 Email would be sent:', {
          to: msg.to,
          subject: msg.subject,
          preview: html.substring(0, 100) + '...'
        });
        
        // Save to email_logs table
        await this.logEmail({
          to: msg.to,
          from: msg.from,
          subject: msg.subject,
          status: 'development',
          metadata: { isDevelopment: true }
        });
        
        return { messageId: 'dev-' + Date.now() };
      }
      
      // Send via SendGrid
      const [response] = await sgMail.send(msg);
      
      // Log successful send
      await this.logEmail({
        to: msg.to,
        from: msg.from,
        subject: msg.subject,
        status: 'sent',
        sent_at: new Date(),
        metadata: { messageId: response.headers['x-message-id'] }
      });
      
      return response;
    } catch (error) {
      console.error('Email send error:', error);
      
      // Log failed send
      await this.logEmail({
        to,
        from: this.from,
        subject,
        status: 'failed',
        metadata: { error: error.message }
      });
      
      throw error;
    }
  }
  
  // Log email
  async logEmail(data) {
    try {
      await db('email_logs').insert({
        id: `email_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        to: data.to,
        from: data.from,
        subject: data.subject,
        template_id: data.template_id,
        status: data.status,
        sent_at: data.sent_at,
        metadata: JSON.stringify(data.metadata || {})
      });
    } catch (error) {
      console.error('Email log error:', error);
    }
  }
  
  // Send welcome email
  async sendWelcomeEmail(email, name) {
    const template = emailTemplates.welcome;
    return await this.send(
      email,
      template.subject,
      template.template(name),
      { template_id: 'welcome' }
    );
  }
  
  // Send password reset email
  async sendPasswordResetEmail(email, name, resetToken) {
    const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
    const template = emailTemplates.passwordReset;
    
    return await this.send(
      email,
      template.subject,
      template.template(name, resetLink),
      { 
        template_id: 'password_reset',
        priority: 'high'
      }
    );
  }
  
  // Send password changed confirmation
  async sendPasswordChangedEmail(email, name) {
    const template = emailTemplates.passwordChanged;
    return await this.send(
      email,
      template.subject,
      template.template(name),
      { 
        template_id: 'password_changed',
        priority: 'high'
      }
    );
  }
  
  // Send workout assigned notification
  async sendWorkoutAssignedEmail(email, clientName, specialistName, workoutName) {
    const template = emailTemplates.workoutAssigned;
    return await this.send(
      email,
      template.subject,
      template.template(clientName, specialistName, workoutName),
      { template_id: 'workout_assigned' }
    );
  }
  
  // Send invoice created notification
  async sendInvoiceEmail(email, clientName, invoiceDetails) {
    const template = emailTemplates.invoiceCreated;
    return await this.send(
      email,
      template.subject,
      template.template(clientName, invoiceDetails),
      { 
        template_id: 'invoice_created',
        attachments: invoiceDetails.attachments
      }
    );
  }
  
  // Send appointment reminder
  async sendAppointmentReminder(email, clientName, sessionDetails) {
    const template = emailTemplates.appointmentReminder;
    return await this.send(
      email,
      template.subject,
      template.template(clientName, sessionDetails),
      { 
        template_id: 'appointment_reminder',
        sendAt: sessionDetails.reminderTime // Schedule for future send
      }
    );
  }
  
  // Send custom email
  async sendCustomEmail(to, subject, html, options = {}) {
    return await this.send(to, subject, html, options);
  }
  
  // Send bulk emails (with rate limiting)
  async sendBulkEmails(recipients, subject, templateFn, options = {}) {
    const results = [];
    const batchSize = 100; // SendGrid recommends max 1000 per request
    const delayBetweenBatches = 1000; // 1 second
    
    for (let i = 0; i < recipients.length; i += batchSize) {
      const batch = recipients.slice(i, i + batchSize);
      
      const personalizations = batch.map(recipient => ({
        to: recipient.email,
        substitutions: recipient.substitutions || {}
      }));
      
      try {
        const msg = {
          personalizations,
          from: this.from,
          subject,
          html: templateFn('{{{name}}}'), // Use substitution syntax
          ...options
        };
        
        if (!this.isDevelopment) {
          await sgMail.sendMultiple(msg);
        }
        
        results.push(...batch.map(r => ({ email: r.email, status: 'sent' })));
        
        // Rate limiting
        if (i + batchSize < recipients.length) {
          await new Promise(resolve => setTimeout(resolve, delayBetweenBatches));
        }
      } catch (error) {
        console.error('Bulk email error:', error);
        results.push(...batch.map(r => ({ email: r.email, status: 'failed', error: error.message })));
      }
    }
    
    return results;
  }
  
  // Verify email configuration
  async verifyConfiguration() {
    try {
      if (this.isDevelopment) {
        console.log('📧 Email service running in development mode');
        return { configured: true, mode: 'development' };
      }
      
      // Test SendGrid API key
      await sgMail.send({
        to: 'test@example.com',
        from: this.from,
        subject: 'Configuration Test',
        text: 'This is a test',
        mailSettings: {
          sandboxMode: {
            enable: true // Don't actually send
          }
        }
      });
      
      return { configured: true, mode: 'production' };
    } catch (error) {
      console.error('Email configuration error:', error);
      return { configured: false, error: error.message };
    }
  }
  
  // Get email statistics
  async getEmailStats(startDate, endDate) {
    try {
      const stats = await db('email_logs')
        .select('status')
        .count('* as count')
        .whereBetween('created_at', [startDate, endDate])
        .groupBy('status');
      
      const templateStats = await db('email_logs')
        .select('template_id')
        .count('* as count')
        .whereBetween('created_at', [startDate, endDate])
        .whereNotNull('template_id')
        .groupBy('template_id');
      
      return {
        statusBreakdown: stats,
        templateBreakdown: templateStats,
        period: { startDate, endDate }
      };
    } catch (error) {
      console.error('Get email stats error:', error);
      return null;
    }
  }
}

// Create and export singleton instance
const emailService = new EmailService();

module.exports = emailService;