const jwt = require('jsonwebtoken');
const { db } = require('../config/database');
const redis = require('../config/redis');

// Store active socket connections
const activeConnections = new Map();

const setupSocketHandlers = (io) => {
  // Authentication middleware for socket connections
  io.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth.token;
      
      if (!token) {
        return next(new Error('Authentication token required'));
      }
      
      // Check if token is blacklisted
      const isBlacklisted = await redis.get(`blacklist_${token}`);
      if (isBlacklisted) {
        return next(new Error('Token is invalid'));
      }
      
      // Verify JWT token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Get user from database
      const user = await db('users')
        .select('id', 'email', 'name', 'roles', 'profile_picture_url')
        .where({ id: decoded.id })
        .first();
      
      if (!user) {
        return next(new Error('User not found'));
      }
      
      // Attach user info to socket
      socket.userId = user.id;
      socket.user = user;
      socket.userRoles = JSON.parse(user.roles);
      
      next();
    } catch (error) {
      console.error('Socket authentication error:', error);
      next(new Error('Authentication failed'));
    }
  });
  
  // Handle new connections
  io.on('connection', async (socket) => {
    console.log(`User ${socket.user.name} (${socket.userId}) connected`);
    
    // Store socket connection
    activeConnections.set(socket.userId, socket.id);
    
    // Join user's personal room for direct notifications
    socket.join(socket.userId);
    
    // Join role-based rooms
    socket.userRoles.forEach(role => {
      socket.join(`role:${role}`);
    });
    
    // Update user's online status
    await updateOnlineStatus(socket.userId, true);
    
    // Broadcast online status to relevant users
    await broadcastOnlineStatus(io, socket.userId, true);
    
    // Get unread message count
    const unreadCount = await getUnreadMessageCount(socket.userId);
    socket.emit('unread-count', { count: unreadCount });
    
    // Load recent conversations
    socket.on('load-conversations', async () => {
      try {
        const conversations = await getRecentConversations(socket.userId);
        socket.emit('conversations-loaded', conversations);
      } catch (error) {
        console.error('Load conversations error:', error);
        socket.emit('error', { message: 'Failed to load conversations' });
      }
    });
    
    // Join a conversation room
    socket.on('join-conversation', async (recipientId) => {
      try {
        // Verify recipient exists
        const recipient = await db('users')
          .select('id', 'name', 'profile_picture_url', 'is_online')
          .where({ id: recipientId })
          .first();
          
        if (!recipient) {
          return socket.emit('error', { message: 'Recipient not found' });
        }
        
        // Check if user has permission to chat with recipient
        const hasPermission = await checkChatPermission(socket.userId, recipientId, socket.userRoles);
        if (!hasPermission) {
          return socket.emit('error', { message: 'You do not have permission to chat with this user' });
        }
        
        // Join conversation room
        const roomId = getConversationRoom(socket.userId, recipientId);
        socket.join(roomId);
        
        // Load message history
        const messages = await loadMessageHistory(socket.userId, recipientId);
        
        // Mark messages as read
        await markMessagesAsRead(recipientId, socket.userId);
        
        // Emit conversation data
        socket.emit('conversation-joined', {
          recipient,
          messages,
          roomId
        });
        
        // Notify recipient that messages were read
        io.to(recipientId).emit('messages-read', {
          conversationWith: socket.userId,
          readBy: socket.userId
        });
      } catch (error) {
        console.error('Join conversation error:', error);
        socket.emit('error', { message: 'Failed to join conversation' });
      }
    });
    
    // Send a message
    socket.on('send-message', async (data) => {
      try {
        const { recipientId, text, attachmentUrl, attachmentType, replyToId } = data;
        
        // Validate input
        if (!recipientId || (!text && !attachmentUrl)) {
          return socket.emit('error', { message: 'Invalid message data' });
        }
        
        // Check permission
        const hasPermission = await checkChatPermission(socket.userId, recipientId, socket.userRoles);
        if (!hasPermission) {
          return socket.emit('error', { message: 'You do not have permission to send messages to this user' });
        }
        
        // Save message to database
        const [message] = await db('messages')
          .insert({
            sender_id: socket.userId,
            recipient_id: recipientId,
            text: text || '',
            attachment_url: attachmentUrl,
            attachment_type: attachmentType,
            reply_to_id: replyToId,
            read: false,
            edited: false,
            reactions: JSON.stringify({})
          })
          .returning('*');
        
        // Add sender info to message
        const enrichedMessage = {
          ...message,
          sender: socket.user,
          reactions: {},
          replyTo: replyToId ? await getMessageById(replyToId) : null
        };
        
        // Send to both users in the conversation
        const roomId = getConversationRoom(socket.userId, recipientId);
        io.to(roomId).emit('new-message', enrichedMessage);
        
        // Update conversation list for both users
        io.to(socket.userId).emit('conversation-updated', {
          userId: recipientId,
          lastMessage: enrichedMessage,
          timestamp: message.created_at
        });
        
        io.to(recipientId).emit('conversation-updated', {
          userId: socket.userId,
          lastMessage: enrichedMessage,
          timestamp: message.created_at
        });
        
        // Send push notification if recipient is offline
        const recipientSocket = activeConnections.get(recipientId);
        if (!recipientSocket) {
          await sendPushNotification(recipientId, {
            title: `New message from ${socket.user.name}`,
            body: text ? text.substring(0, 100) : 'Sent an attachment',
            data: {
              type: 'message',
              senderId: socket.userId,
              messageId: message.id
            }
          });
        }
        
        // Update unread count for recipient
        const unreadCount = await getUnreadMessageCount(recipientId);
        io.to(recipientId).emit('unread-count', { count: unreadCount });
        
        // Log activity
        await db('audit_logs').insert({
          user_id: socket.userId,
          action: 'send_message',
          resource: 'message',
          resource_id: message.id.toString(),
          details: `Sent message to ${recipientId}`,
          metadata: JSON.stringify({ recipientId, hasAttachment: !!attachmentUrl })
        });
      } catch (error) {
        console.error('Send message error:', error);
        socket.emit('error', { message: 'Failed to send message' });
      }
    });
    
    // Typing indicators
    socket.on('typing', ({ recipientId, isTyping }) => {
      const roomId = getConversationRoom(socket.userId, recipientId);
      socket.to(roomId).emit('user-typing', {
        userId: socket.userId,
        userName: socket.user.name,
        isTyping
      });
    });
    
    // Mark messages as read
    socket.on('mark-read', async ({ messageIds, conversationWith }) => {
      try {
        if (!Array.isArray(messageIds) || messageIds.length === 0) {
          return;
        }
        
        // Update messages
        await db('messages')
          .whereIn('id', messageIds)
          .where({ recipient_id: socket.userId, sender_id: conversationWith })
          .update({ read: true });
        
        // Notify sender
        io.to(conversationWith).emit('messages-read', {
          conversationWith: socket.userId,
          messageIds,
          readBy: socket.userId
        });
        
        // Update unread count
        const unreadCount = await getUnreadMessageCount(socket.userId);
        socket.emit('unread-count', { count: unreadCount });
      } catch (error) {
        console.error('Mark read error:', error);
      }
    });
    
    // Edit message
    socket.on('edit-message', async ({ messageId, newText }) => {
      try {
        // Get message
        const message = await db('messages')
          .where({ id: messageId, sender_id: socket.userId })
          .first();
          
        if (!message) {
          return socket.emit('error', { message: 'Message not found or you do not have permission to edit' });
        }
        
        // Update message
        await db('messages')
          .where({ id: messageId })
          .update({
            text: newText,
            edited: true,
            updated_at: new Date()
          });
        
        // Notify both users
        const roomId = getConversationRoom(message.sender_id, message.recipient_id);
        io.to(roomId).emit('message-edited', {
          messageId,
          newText,
          editedAt: new Date()
        });
      } catch (error) {
        console.error('Edit message error:', error);
        socket.emit('error', { message: 'Failed to edit message' });
      }
    });
    
    // Delete message
    socket.on('delete-message', async ({ messageId }) => {
      try {
        // Get message
        const message = await db('messages')
          .where({ id: messageId, sender_id: socket.userId })
          .first();
          
        if (!message) {
          return socket.emit('error', { message: 'Message not found or you do not have permission to delete' });
        }
        
        // Soft delete (mark as deleted but keep in DB)
        await db('messages')
          .where({ id: messageId })
          .update({
            text: '[Message deleted]',
            deleted_at: new Date()
          });
        
        // Notify both users
        const roomId = getConversationRoom(message.sender_id, message.recipient_id);
        io.to(roomId).emit('message-deleted', {
          messageId,
          deletedAt: new Date()
        });
      } catch (error) {
        console.error('Delete message error:', error);
        socket.emit('error', { message: 'Failed to delete message' });
      }
    });
    
    // React to message
    socket.on('react-to-message', async ({ messageId, reaction }) => {
      try {
        // Get message
        const message = await db('messages')
          .where({ id: messageId })
          .first();
          
        if (!message) {
          return socket.emit('error', { message: 'Message not found' });
        }
        
        // Update reactions
        const reactions = JSON.parse(message.reactions || '{}');
        if (!reactions[reaction]) {
          reactions[reaction] = [];
        }
        
        const userIndex = reactions[reaction].indexOf(socket.userId);
        if (userIndex === -1) {
          // Add reaction
          reactions[reaction].push(socket.userId);
        } else {
          // Remove reaction
          reactions[reaction].splice(userIndex, 1);
          if (reactions[reaction].length === 0) {
            delete reactions[reaction];
          }
        }
        
        // Save updated reactions
        await db('messages')
          .where({ id: messageId })
          .update({
            reactions: JSON.stringify(reactions)
          });
        
        // Notify both users
        const roomId = getConversationRoom(message.sender_id, message.recipient_id);
        io.to(roomId).emit('message-reaction-updated', {
          messageId,
          reactions,
          userId: socket.userId,
          reaction
        });
      } catch (error) {
        console.error('React to message error:', error);
        socket.emit('error', { message: 'Failed to add reaction' });
      }
    });
    
    // Voice/Video call signaling
    socket.on('call-user', async ({ recipientId, offer, callType }) => {
      try {
        const recipientSocket = activeConnections.get(recipientId);
        if (!recipientSocket) {
          return socket.emit('user-unavailable', { recipientId });
        }
        
        io.to(recipientId).emit('incoming-call', {
          callerId: socket.userId,
          callerName: socket.user.name,
          callerPicture: socket.user.profile_picture_url,
          offer,
          callType
        });
      } catch (error) {
        console.error('Call user error:', error);
        socket.emit('error', { message: 'Failed to initiate call' });
      }
    });
    
    socket.on('answer-call', ({ callerId, answer }) => {
      io.to(callerId).emit('call-answered', {
        userId: socket.userId,
        answer
      });
    });
    
    socket.on('ice-candidate', ({ recipientId, candidate }) => {
      io.to(recipientId).emit('ice-candidate', {
        userId: socket.userId,
        candidate
      });
    });
    
    socket.on('end-call', ({ recipientId }) => {
      io.to(recipientId).emit('call-ended', {
        userId: socket.userId
      });
    });
    
    // Handle disconnect
    socket.on('disconnect', async () => {
      console.log(`User ${socket.user.name} (${socket.userId}) disconnected`);
      
      // Remove from active connections
      activeConnections.delete(socket.userId);
      
      // Update offline status with delay (user might reconnect)
      setTimeout(async () => {
        if (!activeConnections.has(socket.userId)) {
          await updateOnlineStatus(socket.userId, false);
          await broadcastOnlineStatus(io, socket.userId, false);
        }
      }, 5000); // 5 second delay
    });
  });
};

// Helper functions

// Get conversation room ID (consistent ordering)
const getConversationRoom = (userId1, userId2) => {
  return [userId1, userId2].sort().join(':');
};

// Update user's online status
const updateOnlineStatus = async (userId, isOnline) => {
  try {
    await db('users')
      .where({ id: userId })
      .update({
        is_online: isOnline,
        last_seen: new Date()
      });
  } catch (error) {
    console.error('Update online status error:', error);
  }
};

// Broadcast online status to relevant users
const broadcastOnlineStatus = async (io, userId, isOnline) => {
  try {
    // Get all users who have conversations with this user
    const conversationPartners = await db('messages')
      .distinct('sender_id', 'recipient_id')
      .where('sender_id', userId)
      .orWhere('recipient_id', userId);
    
    const partnerIds = new Set();
    conversationPartners.forEach(row => {
      if (row.sender_id !== userId) partnerIds.add(row.sender_id);
      if (row.recipient_id !== userId) partnerIds.add(row.recipient_id);
    });
    
    // Broadcast to each partner
    partnerIds.forEach(partnerId => {
      io.to(partnerId).emit('user-status-changed', {
        userId,
        isOnline,
        lastSeen: new Date()
      });
    });
  } catch (error) {
    console.error('Broadcast online status error:', error);
  }
};

// Check if user has permission to chat with another user
const checkChatPermission = async (senderId, recipientId, senderRoles) => {
  try {
    // Admins and owners can chat with anyone
    if (senderRoles.includes('admin') || senderRoles.includes('owner')) {
      return true;
    }
    
    // Get recipient
    const recipient = await db('users')
      .select('roles', 'specialist_ids', 'client_ids')
      .where({ id: recipientId })
      .first();
    
    if (!recipient) return false;
    
    const recipientRoles = JSON.parse(recipient.roles);
    
    // Clients can chat with their assigned specialists
    if (senderRoles.includes('client')) {
      const specialistIds = JSON.parse(recipient.specialist_ids || '[]');
      return specialistIds.includes(senderId) || recipientRoles.includes('admin');
    }
    
    // Specialists can chat with their assigned clients
    if (senderRoles.includes('specialist')) {
      const clientIds = JSON.parse(recipient.client_ids || '[]');
      return clientIds.includes(senderId) || recipientRoles.includes('admin');
    }
    
    return false;
  } catch (error) {
    console.error('Check chat permission error:', error);
    return false;
  }
};

// Get recent conversations for a user
const getRecentConversations = async (userId) => {
  try {
    // Get all unique conversation partners
    const conversations = await db.raw(`
      WITH conversation_partners AS (
        SELECT DISTINCT
          CASE 
            WHEN sender_id = ? THEN recipient_id 
            ELSE sender_id 
          END as partner_id,
          MAX(created_at) as last_message_time
        FROM messages
        WHERE sender_id = ? OR recipient_id = ?
        GROUP BY partner_id
      ),
      last_messages AS (
        SELECT DISTINCT ON (
          CASE 
            WHEN m.sender_id = ? THEN m.recipient_id 
            ELSE m.sender_id 
          END
        )
          m.*,
          CASE 
            WHEN m.sender_id = ? THEN m.recipient_id 
            ELSE m.sender_id 
          END as partner_id
        FROM messages m
        WHERE m.sender_id = ? OR m.recipient_id = ?
        ORDER BY partner_id, m.created_at DESC
      )
      SELECT 
        u.id,
        u.name,
        u.email,
        u.profile_picture_url,
        u.is_online,
        u.last_seen,
        lm.id as last_message_id,
        lm.text as last_message_text,
        lm.created_at as last_message_time,
        lm.sender_id as last_message_sender,
        lm.read as last_message_read,
        COUNT(CASE WHEN m2.read = false AND m2.recipient_id = ? THEN 1 END) as unread_count
      FROM conversation_partners cp
      JOIN users u ON u.id = cp.partner_id
      LEFT JOIN last_messages lm ON lm.partner_id = cp.partner_id
      LEFT JOIN messages m2 ON (m2.sender_id = cp.partner_id AND m2.recipient_id = ?)
      GROUP BY u.id, u.name, u.email, u.profile_picture_url, u.is_online, u.last_seen,
               lm.id, lm.text, lm.created_at, lm.sender_id, lm.read, cp.last_message_time
      ORDER BY cp.last_message_time DESC
    `, [userId, userId, userId, userId, userId, userId, userId, userId, userId]);
    
    return conversations.rows;
  } catch (error) {
    console.error('Get recent conversations error:', error);
    return [];
  }
};

// Load message history between two users
const loadMessageHistory = async (userId1, userId2, limit = 50) => {
  try {
    const messages = await db('messages')
      .select(
        'messages.*',
        'sender.name as sender_name',
        'sender.profile_picture_url as sender_picture',
        'recipient.name as recipient_name',
        'recipient.profile_picture_url as recipient_picture'
      )
      .leftJoin('users as sender', 'messages.sender_id', 'sender.id')
      .leftJoin('users as recipient', 'messages.recipient_id', 'recipient.id')
      .where(function() {
        this.where({ sender_id: userId1, recipient_id: userId2 })
          .orWhere({ sender_id: userId2, recipient_id: userId1 });
      })
      .whereNull('deleted_at')
      .orderBy('created_at', 'desc')
      .limit(limit);
    
    // Parse reactions and format messages
    const formattedMessages = messages.map(msg => ({
      ...msg,
      reactions: JSON.parse(msg.reactions || '{}'),
      sender: {
        id: msg.sender_id,
        name: msg.sender_name,
        profilePicture: msg.sender_picture
      },
      recipient: {
        id: msg.recipient_id,
        name: msg.recipient_name,
        profilePicture: msg.recipient_picture
      }
    }));
    
    return formattedMessages.reverse(); // Return in chronological order
  } catch (error) {
    console.error('Load message history error:', error);
    return [];
  }
};

// Mark messages as read
const markMessagesAsRead = async (senderId, recipientId) => {
  try {
    await db('messages')
      .where({
        sender_id: senderId,
        recipient_id: recipientId,
        read: false
      })
      .update({ read: true });
  } catch (error) {
    console.error('Mark messages as read error:', error);
  }
};

// Get unread message count
const getUnreadMessageCount = async (userId) => {
  try {
    const [{ count }] = await db('messages')
      .where({
        recipient_id: userId,
        read: false
      })
      .whereNull('deleted_at')
      .count('* as count');
    
    return parseInt(count);
  } catch (error) {
    console.error('Get unread count error:', error);
    return 0;
  }
};

// Get message by ID
const getMessageById = async (messageId) => {
  try {
    return await db('messages')
      .where({ id: messageId })
      .first();
  } catch (error) {
    console.error('Get message by ID error:', error);
    return null;
  }
};

// Send push notification (placeholder - implement with FCM/APNS)
const sendPushNotification = async (userId, notification) => {
  try {
    // In production, this would:
    // 1. Get user's push tokens from database
    // 2. Send via Firebase Cloud Messaging or Apple Push Notification Service
    console.log(`Push notification for user ${userId}:`, notification);
  } catch (error) {
    console.error('Send push notification error:', error);
  }
};

module.exports = setupSocketHandlers;