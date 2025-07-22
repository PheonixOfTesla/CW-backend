const twilio = require('twilio');
const { db } = require('../config/database');

// SMS templates
const smsTemplates = {
  twoFactorCode: (code) => 
    `Your ClockWork verification code is: ${code}\n\nThis code expires in 5 minutes. Never share this code with anyone.`,
  
  appointmentReminder: (clientName, sessionDetails) => 
    `Hi ${clientName}! Reminder: You have a ${sessionDetails.type} session tomorrow at ${sessionDetails.time} with ${sessionDetails.trainerName}. Reply CONFIRM to confirm or CANCEL to cancel.`,
  
  appointmentConfirmation: (sessionDetails) => 
    `Your ${sessionDetails.type} session on ${sessionDetails.date} at ${sessionDetails.time} has been confirmed. See you there!`,
  
  appointmentCancellation: (sessionDetails) => 
    `Your ${sessionDetails.type} session on ${sessionDetails.date} at ${sessionDetails.time} has been cancelled. Contact your specialist to reschedule.`,
  
  workoutReminder: (clientName) => 
    `Hey ${clientName}! Time for your scheduled workout today. Open ClockWork to view your plan and track your progress! 💪`,
  
  paymentReminder: (clientName, amount) => 
    `Hi ${clientName}, friendly reminder: You have an outstanding invoice of $${amount}. Login to ClockWork to view and pay. Thank you!`,
  
  welcome: (name) => 
    `Welcome to ClockWork, ${name}! 🎉 Your journey to better health starts now. Login at ${process.env.FRONTEND_URL} to get started.`
};

// SMS Service class
class SMSService {
  constructor() {
    this.isDevelopment = process.env.NODE_ENV === 'development';
    this.fromNumber = process.env.TWILIO_PHONE_NUMBER;
    
    if (!this.isDevelopment && process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
      this.client = twilio(
        process.env.TWILIO_ACCOUNT_SID,
        process.env.TWILIO_AUTH_TOKEN
      );
    }
    
    // Rate limiting tracking
    this.rateLimits = new Map();
    this.maxSMSPerHour = 10; // Per phone number
    this.maxSMSPerDay = 50; // Per phone number
  }
  
  // Check rate limits
  checkRateLimit(phoneNumber) {
    const now = Date.now();
    const hourAgo = now - (60 * 60 * 1000);
    const dayAgo = now - (24 * 60 * 60 * 1000);
    
    if (!this.rateLimits.has(phoneNumber)) {
      this.rateLimits.set(phoneNumber, []);
    }
    
    const sends = this.rateLimits.get(phoneNumber);
    
    // Clean up old entries
    const recentSends = sends.filter(timestamp => timestamp > dayAgo);
    this.rateLimits.set(phoneNumber, recentSends);
    
    // Check hourly limit
    const hourSends = recentSends.filter(timestamp => timestamp > hourAgo);
    if (hourSends.length >= this.maxSMSPerHour) {
      throw new Error('Hourly SMS limit exceeded for this number');
    }
    
    // Check daily limit
    if (recentSends.length >= this.maxSMSPerDay) {
      throw new Error('Daily SMS limit exceeded for this number');
    }
    
    return true;
  }
  
  // Record SMS send for rate limiting
  recordSend(phoneNumber) {
    const sends = this.rateLimits.get(phoneNumber) || [];
    sends.push(Date.now());
    this.rateLimits.set(phoneNumber, sends);
  }
  
  // Validate phone number
  validatePhoneNumber(phoneNumber) {
    // Remove all non-numeric characters
    const cleaned = phoneNumber.replace(/\D/g, '');
    
    // Check if it's a valid length (10 digits for US, 11 if includes country code)
    if (cleaned.length === 10) {
      return `+1${cleaned}`;
    } else if (cleaned.length === 11 && cleaned.startsWith('1')) {
      return `+${cleaned}`;
    } else if (cleaned.length > 10 && cleaned.startsWith('+')) {
      return phoneNumber; // Already in international format
    }
    
    throw new Error('Invalid phone number format');
  }
  
  // Send SMS
  async send(to, message, options = {}) {
    try {
      // Validate phone number
      const formattedTo = this.validatePhoneNumber(to);
      
      // Check rate limits
      this.checkRateLimit(formattedTo);
      
      // Log SMS attempt
      const logData = {
        to: formattedTo,
        message: message.substring(0, 50) + '...',
        type: options.type || 'general',
        status: 'pending'
      };
      
      if (this.isDevelopment || !this.client) {
        // In development, just log the SMS
        console.log('📱 SMS would be sent:', {
          to: formattedTo,
          message,
          from: this.fromNumber
        });
        
        await this.logSMS({
          ...logData,
          status: 'development',
          metadata: { isDevelopment: true }
        });
        
        return { sid: 'dev-' + Date.now(), status: 'development' };
      }
      
      // Send via Twilio
      const result = await this.client.messages.create({
        body: message,
        to: formattedTo,
        from: this.fromNumber,
        ...options.twilioOptions
      });
      
      // Record successful send
      this.recordSend(formattedTo);
      
      // Log successful send
      await this.logSMS({
        ...logData,
        status: 'sent',
        sid: result.sid,
        metadata: {
          price: result.price,
          priceUnit: result.priceUnit,
          errorCode: result.errorCode,
          errorMessage: result.errorMessage
        }
      });
      
      return result;
    } catch (error) {
      console.error('SMS send error:', error);
      
      // Log failed send
      await this.logSMS({
        to,
        message: message.substring(0, 50) + '...',
        type: options.type || 'general',
        status: 'failed',
        metadata: { error: error.message }
      });
      
      throw error;
    }
  }
  
  // Log SMS to database
  async logSMS(data) {
    try {
      await db('sms_logs').insert({
        id: `sms_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        to: data.to,
        from: this.fromNumber,
        message: data.message,
        type: data.type,
        status: data.status,
        sid: data.sid,
        sent_at: data.status === 'sent' ? new Date() : null,
        metadata: JSON.stringify(data.metadata || {})
      });
    } catch (error) {
      console.error('SMS log error:', error);
    }
  }
  
  // Send 2FA code
  async sendTwoFactorCode(phoneNumber, code) {
    return await this.send(
      phoneNumber,
      smsTemplates.twoFactorCode(code),
      { type: '2fa' }
    );
  }
  
  // Send appointment reminder
  async sendAppointmentReminder(phoneNumber, clientName, sessionDetails) {
    return await this.send(
      phoneNumber,
      smsTemplates.appointmentReminder(clientName, sessionDetails),
      { type: 'appointment_reminder' }
    );
  }
  
  // Send appointment confirmation
  async sendAppointmentConfirmation(phoneNumber, sessionDetails) {
    return await this.send(
      phoneNumber,
      smsTemplates.appointmentConfirmation(sessionDetails),
      { type: 'appointment_confirmation' }
    );
  }
  
  // Send appointment cancellation
  async sendAppointmentCancellation(phoneNumber, sessionDetails) {
    return await this.send(
      phoneNumber,
      smsTemplates.appointmentCancellation(sessionDetails),
      { type: 'appointment_cancellation' }
    );
  }
  
  // Send workout reminder
  async sendWorkoutReminder(phoneNumber, clientName) {
    return await this.send(
      phoneNumber,
      smsTemplates.workoutReminder(clientName),
      { type: 'workout_reminder' }
    );
  }
  
  // Send payment reminder
  async sendPaymentReminder(phoneNumber, clientName, amount) {
    return await this.send(
      phoneNumber,
      smsTemplates.paymentReminder(clientName, amount.toFixed(2)),
      { type: 'payment_reminder' }
    );
  }
  
  // Send welcome SMS
  async sendWelcomeSMS(phoneNumber, name) {
    return await this.send(
      phoneNumber,
      smsTemplates.welcome(name),
      { type: 'welcome' }
    );
  }
  
  // Send custom SMS
  async sendCustomSMS(to, message, options = {}) {
    return await this.send(to, message, { ...options, type: 'custom' });
  }
  
  // Handle incoming SMS (webhooks)
  async handleIncomingSMS(from, body, messageSid) {
    try {
      // Log incoming message
      await this.logSMS({
        to: this.fromNumber,
        from,
        message: body,
        type: 'incoming',
        status: 'received',
        sid: messageSid
      });
      
      // Parse message for keywords
      const upperBody = body.toUpperCase().trim();
      
      // Handle appointment confirmations/cancellations
      if (upperBody === 'CONFIRM' || upperBody === 'CANCEL') {
        await this.handleAppointmentResponse(from, upperBody);
      }
      
      // Handle STOP/UNSUBSCRIBE
      else if (upperBody === 'STOP' || upperBody === 'UNSUBSCRIBE') {
        await this.handleOptOut(from);
      }
      
      // Handle START/SUBSCRIBE
      else if (upperBody === 'START' || upperBody === 'SUBSCRIBE') {
        await this.handleOptIn(from);
      }
      
      // Default response
      else {
        await this.send(
          from,
          'Thank you for your message. For support, please login to ClockWork or email support@clockwork.platform',
          { type: 'auto_reply' }
        );
      }
    } catch (error) {
      console.error('Handle incoming SMS error:', error);
    }
  }
  
  // Handle appointment response
  async handleAppointmentResponse(phoneNumber, response) {
    try {
      // Find user by phone number
      const user = await db('users')
        .where({ phone: phoneNumber })
        .first();
      
      if (!user) {
        return await this.send(
          phoneNumber,
          'We couldn\'t find your account. Please contact support.',
          { type: 'auto_reply' }
        );
      }
      
      // Find upcoming appointment
      const session = await db('training_sessions')
        .where({
          client_id: user.id,
          status: 'scheduled'
        })
        .where('date', '>=', new Date())
        .orderBy('date', 'asc')
        .orderBy('time', 'asc')
        .first();
      
      if (!session) {
        return await this.send(
          phoneNumber,
          'No upcoming appointments found.',
          { type: 'auto_reply' }
        );
      }
      
      if (response === 'CONFIRM') {
        await db('training_sessions')
          .where({ id: session.id })
          .update({ 
            status: 'confirmed',
            updated_at: new Date()
          });
        
        await this.sendAppointmentConfirmation(phoneNumber, session);
      } else if (response === 'CANCEL') {
        await db('training_sessions')
          .where({ id: session.id })
          .update({ 
            status: 'cancelled',
            updated_at: new Date()
          });
        
        await this.sendAppointmentCancellation(phoneNumber, session);
      }
    } catch (error) {
      console.error('Handle appointment response error:', error);
    }
  }
  
  // Handle opt-out
  async handleOptOut(phoneNumber) {
    try {
      await db('users')
        .where({ phone: phoneNumber })
        .update({
          sms_opt_out: true,
          sms_opt_out_date: new Date()
        });
      
      await this.send(
        phoneNumber,
        'You have been unsubscribed from ClockWork SMS notifications. Reply START to resubscribe.',
        { type: 'opt_out_confirmation' }
      );
    } catch (error) {
      console.error('Handle opt-out error:', error);
    }
  }
  
  // Handle opt-in
  async handleOptIn(phoneNumber) {
    try {
      await db('users')
        .where({ phone: phoneNumber })
        .update({
          sms_opt_out: false,
          sms_opt_out_date: null
        });
      
      await this.send(
        phoneNumber,
        'Welcome back! You have been resubscribed to ClockWork SMS notifications.',
        { type: 'opt_in_confirmation' }
      );
    } catch (error) {
      console.error('Handle opt-in error:', error);
    }
  }
  
  // Verify Twilio configuration
  async verifyConfiguration() {
    try {
      if (this.isDevelopment || !this.client) {
        console.log('📱 SMS service running in development mode');
        return { configured: true, mode: 'development' };
      }
      
      // Test Twilio connection
      const phoneNumbers = await this.client.incomingPhoneNumbers.list({ limit: 1 });
      
      return {
        configured: true,
        mode: 'production',
        phoneNumber: this.fromNumber,
        phoneNumbersCount: phoneNumbers.length
      };
    } catch (error) {
      console.error('SMS configuration error:', error);
      return { configured: false, error: error.message };
    }
  }
  
  // Get SMS statistics
  async getSMSStats(startDate, endDate) {
    try {
      const stats = await db('sms_logs')
        .select('status', 'type')
        .count('* as count')
        .whereBetween('created_at', [startDate, endDate])
        .groupBy('status', 'type');
      
      const costs = await db('sms_logs')
        .select(db.raw("SUM((metadata->>'price')::numeric) as total_cost"))
        .whereBetween('created_at', [startDate, endDate])
        .where('status', 'sent')
        .first();
      
      return {
        breakdown: stats,
        totalCost: costs.total_cost || 0,
        period: { startDate, endDate }
      };
    } catch (error) {
      console.error('Get SMS stats error:', error);
      return null;
    }
  }
  
  // Send bulk SMS (with rate limiting and batching)
  async sendBulkSMS(recipients, messageTemplate, options = {}) {
    const results = [];
    const batchSize = 10; // Send 10 at a time
    const delayBetweenBatches = 1000; // 1 second
    
    for (let i = 0; i < recipients.length; i += batchSize) {
      const batch = recipients.slice(i, i + batchSize);
      
      const batchPromises = batch.map(async (recipient) => {
        try {
          const message = typeof messageTemplate === 'function' 
            ? messageTemplate(recipient)
            : messageTemplate;
          
          await this.send(recipient.phone, message, {
            ...options,
            type: options.type || 'bulk'
          });
          
          return { phone: recipient.phone, status: 'sent' };
        } catch (error) {
          return { phone: recipient.phone, status: 'failed', error: error.message };
        }
      });
      
      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
      
      // Rate limiting between batches
      if (i + batchSize < recipients.length) {
        await new Promise(resolve => setTimeout(resolve, delayBetweenBatches));
      }
    }
    
    return results;
  }
}

// Create table for SMS logs if not exists (migration should handle this)
const createSMSLogsTable = `
  CREATE TABLE IF NOT EXISTS sms_logs (
    id VARCHAR(255) PRIMARY KEY,
    to VARCHAR(20) NOT NULL,
    from VARCHAR(20),
    message TEXT,
    type VARCHAR(50),
    status VARCHAR(20),
    sid VARCHAR(255),
    sent_at TIMESTAMP,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE INDEX IF NOT EXISTS idx_sms_logs_to ON sms_logs(to);
  CREATE INDEX IF NOT EXISTS idx_sms_logs_status ON sms_logs(status);
  CREATE INDEX IF NOT EXISTS idx_sms_logs_created_at ON sms_logs(created_at);
`;

// Create and export singleton instance
const smsService = new SMSService();

module.exports = smsService;