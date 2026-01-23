const express = require('express');
const mongoose = require('mongoose');
const socketIO = require('socket.io');
const http = require('http');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

// Initialize Express
const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
  cors: {
    origin: ['http://localhost:3000', 'https://schat-q1nj.onrender.com'],
    credentials: true
  },
  transports: ['websocket', 'polling']
});

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'https://schat-q1nj.onrender.com'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/')
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB limit
  },
  fileFilter: (req, file, cb) => {
    // Accept all file types
    cb(null, true);
  }
});

// Helper function to determine media type
function getMediaType(mimeType) {
  if (mimeType.startsWith('image/')) return 'image';
  if (mimeType.startsWith('video/')) return 'video';
  if (mimeType.startsWith('audio/')) return 'audio';
  if (mimeType.includes('pdf')) return 'document';
  if (mimeType.includes('word') || mimeType.includes('document')) return 'document';
  return 'file';
}

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

// ==================== MODELS ====================

// User Model
const UserSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  nickname: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  bio: { type: String, default: '' },
  university: { type: String, required: true },
  studyGroup: { type: String, required: true },
  phone: { type: String, required: true, unique: true },
  email: { type: String, default: '' },
  password: { type: String, required: true },
  avatar: { type: String, default: 'https://res.cloudinary.com/demo/image/upload/v1692290000/default-avatar.png' },
  isOnline: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now },
  lastUsernameChange: { type: Date, default: null },
  socketId: { type: String, default: '' },
  status: { 
    type: String, 
    enum: ['online', 'offline', 'away', 'busy'], 
    default: 'offline' 
  },
  lastActive: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

// Message Model (1v1)
const MessageSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, default: '' },
  mediaUrl: { type: String, default: '' },
  mediaType: { type: String, enum: ['image', 'video', 'audio', 'document', 'voice', 'file', ''], default: '' },
  isRead: { type: Boolean, default: false },
  isDelivered: { type: Boolean, default: false },
  mediaMetadata: {
    fileName: String,
    fileSize: Number,
    mimeType: String,
    duration: String,
    thumbnail: String
  },
  createdAt: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', MessageSchema);

// Call History Model
const CallHistorySchema = new mongoose.Schema({
  callerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['audio', 'video'], required: true },
  status: { type: String, enum: ['missed', 'completed', 'rejected', 'cancelled', 'initiated'], required: true },
  duration: { type: Number, default: 0 }, // in seconds
  startedAt: { type: Date, default: Date.now },
  endedAt: { type: Date }
});
const CallHistory = mongoose.model('CallHistory', CallHistorySchema);

// Group Model
const GroupSchema = new mongoose.Schema({
  name: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  description: { type: String, default: '' },
  creatorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  avatar: { type: String, default: 'https://res.cloudinary.com/demo/image/upload/v1692290000/default-group.png' },
  createdAt: { type: Date, default: Date.now },
  isPublic: { type: Boolean, default: true }
});
const Group = mongoose.model('Group', GroupSchema);

// Group Message Model
const GroupMessageSchema = new mongoose.Schema({
  groupId: { type: mongoose.Schema.Types.ObjectId, ref: 'Group', required: true },
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, default: '' },
  mediaUrl: { type: String, default: '' },
  mediaType: { type: String, enum: ['image', 'video', 'audio', 'document', 'voice', 'file', ''], default: '' },
  createdAt: { type: Date, default: Date.now }
});
const GroupMessage = mongoose.model('GroupMessage', GroupMessageSchema);

// Channel Model
const ChannelSchema = new mongoose.Schema({
  name: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  description: { type: String, default: '' },
  creatorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  subscribers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  moderators: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  avatar: { type: String, default: 'https://res.cloudinary.com/demo/image/upload/v1692290000/default-channel.png' },
  category: { type: String, default: 'other' },
  university: { type: String, default: '' },
  isPublic: { type: Boolean, default: true },
  inviteLink: { type: String },
  createdAt: { type: Date, default: Date.now }
});
const Channel = mongoose.model('Channel', ChannelSchema);

// Channel Post Model
const ChannelPostSchema = new mongoose.Schema({
  channelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Channel', required: true },
  content: { type: String, required: true },
  mediaUrl: { type: String, default: '' },
  mediaType: { type: String, enum: ['image', 'video', 'audio', 'document', ''], default: '' },
  type: { type: String, enum: ['announcement', 'post', 'media'], default: 'post' },
  viewsCount: { type: Number, default: 0 },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});
const ChannelPost = mongoose.model('ChannelPost', ChannelPostSchema);

// Stats Model
const StatsSchema = new mongoose.Schema({
  totalUsers: { type: Number, default: 0 },
  totalMessages: { type: Number, default: 0 },
  totalGroups: { type: Number, default: 0 },
  totalChannels: { type: Number, default: 0 },
  dailyVisits: { type: Number, default: 0 },
  lastReset: { type: Date, default: Date.now }
});
const Stats = mongoose.model('Stats', StatsSchema);

// Initialize Stats
async function initializeStats() {
  const stats = await Stats.findOne();
  if (!stats) {
    await Stats.create({});
  }
}

// ==================== AUTHENTICATION MIDDLEWARE ====================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// ==================== HELPER FUNCTIONS ====================
// A user can have multiple active sockets (multiple tabs/devices).
function getUserSocketIds(userId) {
  const userData = onlineUsers.get(userId);
  if (!userData) return [];
  // Backward compatibility if old shape is present
  if (userData.socketId) return [userData.socketId];
  return Array.from(userData.sockets || []);
}

// Backward-compatible helper: returns the first socketId if available.
function getUserSocketId(userId) {
  return getUserSocketIds(userId)[0] || null;
}

function emitToUser(userId, event, payload) {
  const socketIds = getUserSocketIds(userId);
  socketIds.forEach((sid) => io.to(sid).emit(event, payload));
}

function isUserOnline(userId) {
  return getUserSocketIds(userId).length > 0;
}

function getChatRoomName(userId1, userId2) {
  const sortedIds = [userId1, userId2].sort();
  return `chat_${sortedIds[0]}_${sortedIds[1]}`;
}

// ==================== SOCKET.IO ====================
// Presence state (in-memory)
// onlineUsers: userId -> { sockets: Set<string>, lastActive: number, lastDbUpdate?: number }
// userSockets: socketId -> userId
const onlineUsers = new Map();
const userSockets = new Map();

function addUserSocket(userId, socketId) {
  const existing = onlineUsers.get(userId) || { sockets: new Set(), lastActive: Date.now() };
  if (!existing.sockets) existing.sockets = new Set();
  existing.sockets.add(socketId);
  existing.lastActive = Date.now();
  onlineUsers.set(userId, existing);
  userSockets.set(socketId, userId);
}

function removeUserSocket(userId, socketId) {
  const existing = onlineUsers.get(userId);
  if (!existing) return { becameOffline: true };
  if (existing.sockets) existing.sockets.delete(socketId);
  userSockets.delete(socketId);
  const stillOnline = existing.sockets && existing.sockets.size > 0;
  if (!stillOnline) {
    onlineUsers.delete(userId);
    return { becameOffline: true };
  }
  onlineUsers.set(userId, existing);
  return { becameOffline: false };
}

io.on('connection', (socket) => {
  console.log('🔌 New client connected:', socket.id);
  
  // User authentication via socket
  socket.on('authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const userId = decoded.userId.toString();
      
      // Store socket with user ID (supports multi-tab / multi-device)
      const wasOnline = isUserOnline(userId);
      addUserSocket(userId, socket.id);
      socket.userId = userId;
      
      // Update user status in database only when the user becomes online
      if (!wasOnline) {
        await User.findByIdAndUpdate(userId, {
          isOnline: true,
          lastSeen: Date.now(),
          lastActive: Date.now(),
          socketId: socket.id
        });
      } else {
        // Keep lastActive fresh, but don't flip status unnecessarily
        await User.findByIdAndUpdate(userId, {
          lastActive: Date.now(),
          socketId: socket.id
        });
      }
      
      console.log('✅ User authenticated:', userId);
      
      // Join user's personal room
      socket.join(userId);
      socket.join(`user_${userId}`);
      
      // Presence broadcast: show ONLINE to everyone (requirement)
      if (!wasOnline) {
        io.emit('userOnline', { userId, timestamp: Date.now() });
      }
      
      // Send confirmation to client
      socket.emit('authenticated', { 
        success: true, 
        userId: userId,
        socketId: socket.id
      });
      
    } catch (error) {
      console.error('❌ Socket authentication error:', error);
      socket.emit('authenticationError', { error: 'Invalid token' });
      socket.disconnect();
    }
  });
  
  // Join chat room
  socket.on('joinChat', async ({ userId, targetUserId }) => {
    try {
      const roomName = getChatRoomName(userId, targetUserId);
      socket.join(roomName);
      console.log(`👥 User ${userId} joined chat room: ${roomName}`);
      
      socket.emit('chatJoined', { roomName });
    } catch (error) {
      console.error('Join chat error:', error);
    }
  });
  
  // Leave chat room
  socket.on('leaveChat', ({ userId, targetUserId }) => {
    const roomName = getChatRoomName(userId, targetUserId);
    socket.leave(roomName);
    console.log(`👋 User ${userId} left chat room: ${roomName}`);
  });
  
  // Private message (1v1 chat)
  socket.on('privateMessage', async (data) => {
    try {
      const { senderId, receiverId, text, mediaUrl, mediaType, mediaMetadata, clientTempId } = data;
      
      console.log(`📨 Message from ${senderId} to ${receiverId}:`, text?.substring(0, 50));
      
      // Normalize mediaType:
      // - Client may send '' for plain text
      // - Older clients may send 'text' (not in enum)
      const normalizedMediaType = (typeof mediaType === 'string' && mediaType.trim() === 'text')
        ? ''
        : (mediaType || '');

      const message = new Message({
        senderId: senderId,
        receiverId: receiverId,
        text: text || '',
        mediaUrl: mediaUrl || '',
        mediaType: normalizedMediaType,
        mediaMetadata: mediaMetadata,
        isRead: false,
        isDelivered: false
      });
      
      await message.save();
      
      // Update stats
      await Stats.findOneAndUpdate({}, { $inc: { totalMessages: 1 } });
      
      const populatedMessageDoc = await Message.findById(message._id)
        .populate('senderId', 'username nickname avatar')
        .populate('receiverId', 'username nickname avatar');

      // Attach clientTempId (used for optimistic UI reconciliation)
      const populatedMessage = populatedMessageDoc.toObject();
      if (clientTempId) populatedMessage.clientTempId = clientTempId;
      
      const roomName = getChatRoomName(senderId, receiverId);
      
      // Emit to the chat room (both users will receive)
      io.to(roomName).emit('newMessage', populatedMessage);
      
      // Mark as delivered if receiver is in room
      const receiverSocketId = getUserSocketId(receiverId);
      if (receiverSocketId) {
        message.isDelivered = true;
        await message.save();
        
        io.to(receiverSocketId).emit('messageNotification', {
          message: populatedMessage,
          unreadCount: await Message.countDocuments({
            receiverId: receiverId,
            senderId: senderId,
            isRead: false
          })
        });
      }
      
      // Update sender's socket about message sent
      const senderSocketId = getUserSocketId(senderId);
      if (senderSocketId) {
        io.to(senderSocketId).emit('messageSent', populatedMessage);
      }
      
    } catch (error) {
      console.error('❌ Error sending private message:', error);
      socket.emit('messageError', { error: 'Failed to send message' });
    }
  });
  
  // Typing indicator
  socket.on('typing', (data) => {
    const { userId, isTyping } = data;
    
    if (userId && socket.userId) {
      const targetSocketId = getUserSocketId(userId);
      if (targetSocketId) {
        io.to(targetSocketId).emit('userTyping', { 
          userId: socket.userId, 
          isTyping: isTyping,
          timestamp: Date.now()
        });
      }
    }
  });
  
  // Mark message as read
  socket.on('markMessageRead', async (data) => {
    try {
      const { messageId, readerId } = data;
      
      const message = await Message.findById(messageId);
      if (message && message.receiverId.toString() === readerId) {
        message.isRead = true;
        await message.save();
        
        const senderSocketId = getUserSocketId(message.senderId.toString());
        if (senderSocketId) {
          io.to(senderSocketId).emit('messageRead', {
            messageId: messageId,
            readerId: readerId,
            timestamp: Date.now()
          });
        }
      }
    } catch (error) {
      console.error('❌ Error marking message as read:', error);
    }
  });
  
  // Mark messages as delivered
  socket.on('markMessagesDelivered', async (data) => {
    try {
      const { messageIds, userId } = data;
      
      await Message.updateMany(
        { _id: { $in: messageIds }, receiverId: userId },
        { isDelivered: true }
      );
      
      const messages = await Message.find({ _id: { $in: messageIds } });
      messages.forEach(async (message) => {
        const senderSocketId = getUserSocketId(message.senderId.toString());
        if (senderSocketId) {
          io.to(senderSocketId).emit('messageDelivered', {
            messageId: message._id,
            receiverId: userId,
            timestamp: Date.now()
          });
        }
      });
    } catch (error) {
      console.error('Error marking messages delivered:', error);
    }
  });
  
  // WebRTC Signaling
  
  // Call offer
  socket.on('callOffer', async (data) => {
    try {
      console.log('📞 Call offer from:', socket.userId, 'to:', data.to, 'type:', data.type);
      
      const receiver = await User.findById(data.to);
      if (!receiver) {
        socket.emit('callError', { error: 'User not found' });
        return;
      }
      
      if (!isUserOnline(data.to)) {
        const callHistory = new CallHistory({
          callerId: socket.userId,
          receiverId: data.to,
          type: data.type,
          status: 'missed',
          duration: 0
        });
        await callHistory.save();
        
        socket.emit('callError', { error: 'User is offline' });
        return;
      }
      
      const callHistory = new CallHistory({
        callerId: socket.userId,
        receiverId: data.to,
        type: data.type,
        status: 'initiated',
        duration: 0
      });
      await callHistory.save();
      
      const caller = await User.findById(socket.userId).select('username nickname avatar');
      
      const offerData = {
        ...data,
        from: socket.userId,
        callerInfo: {
          userId: socket.userId,
          nickname: caller.nickname,
          avatar: caller.avatar,
          callId: callHistory._id,
          timestamp: Date.now()
        }
      };
      
      emitToUser(data.to, 'callOffer', offerData);
      
      console.log(`📞 Call offer sent to ${data.to}`);
      
    } catch (error) {
      console.error('Call offer error:', error);
      socket.emit('callError', { error: 'Failed to initiate call' });
    }
  });
  
  // Call answer
  socket.on('callAnswer', async (data) => {
    try {
      console.log('✅ Call answer from:', socket.userId, 'to:', data.to);
      
      if (data.callId) {
        await CallHistory.findByIdAndUpdate(data.callId, {
          status: data.answer ? 'accepted' : 'rejected'
        });
      }
      
      const answerData = {
        ...data,
        from: socket.userId,
        timestamp: Date.now()
      };
      
      emitToUser(data.to, 'callAnswer', answerData);
      
    } catch (error) {
      console.error('Call answer error:', error);
    }
  });
  
  // ICE candidate
  socket.on('iceCandidate', (data) => {
    console.log('❄️ ICE candidate from:', socket.userId, 'to:', data.to);
    
    const candidateData = {
      ...data,
      from: socket.userId,
      timestamp: Date.now()
    };
    
    emitToUser(data.to, 'iceCandidate', candidateData);
  });
  
  // Call ended
  socket.on('callEnded', async (data) => {
    try {
      console.log('📞 Call ended from:', socket.userId, 'to:', data.to);
      
      if (data.callId) {
        await CallHistory.findByIdAndUpdate(data.callId, {
          status: 'completed',
          duration: data.duration || 0,
          endedAt: Date.now()
        });
      }
      
      const endData = {
        ...data,
        from: socket.userId,
        timestamp: Date.now()
      };
      
      emitToUser(data.to, 'callEnded', endData);
      
      if (data.roomId) {
        io.to(data.roomId).emit('callEnded', endData);
      }
      
    } catch (error) {
      console.error('Call ended error:', error);
    }
  });
  
  // Call rejected
  socket.on('callRejected', async (data) => {
    try {
      console.log('❌ Call rejected from:', socket.userId, 'to:', data.to);
      
      if (data.callId) {
        await CallHistory.findByIdAndUpdate(data.callId, {
          status: 'rejected',
          endedAt: Date.now()
        });
      }
      
      const rejectData = {
        ...data,
        from: socket.userId,
        timestamp: Date.now()
      };
      
      emitToUser(data.to, 'callRejected', rejectData);
    } catch (error) {
      console.error('Call rejected error:', error);
    }
  });
  
  // Call missed
  socket.on('callMissed', async (data) => {
    try {
      console.log('📞 Call missed from:', socket.userId, 'to:', data.to);
      
      if (data.callId) {
        await CallHistory.findByIdAndUpdate(data.callId, {
          status: 'missed',
          endedAt: Date.now()
        });
      }
    } catch (error) {
      console.error('Call missed error:', error);
    }
  });
  
  // Call timeout (no answer)
  socket.on('callTimeout', async (data) => {
    try {
      console.log('⏰ Call timeout from:', socket.userId, 'to:', data.to);
      
      if (data.callId) {
        await CallHistory.findByIdAndUpdate(data.callId, {
          status: 'missed',
          endedAt: Date.now()
        });
      }
      
      emitToUser(data.to, 'callTimeout', {
        to: data.to,
        callId: data.callId,
        timestamp: Date.now()
      });
    } catch (error) {
      console.error('Call timeout error:', error);
    }
  });
  
  // Get online status
  socket.on('checkOnline', (data) => {
    const { userId } = data;
    const userData = onlineUsers.get(userId);
    const isOnline = isUserOnline(userId);
    
    socket.emit('onlineStatus', { 
      userId, 
      isOnline,
      lastActive: userData?.lastActive 
    });
  });
  
  // Get online users
  socket.on('getOnlineUsers', () => {
    const onlineUserIds = Array.from(onlineUsers.keys());
    socket.emit('onlineUsersList', { 
      users: onlineUserIds,
      count: onlineUserIds.length,
      timestamp: Date.now()
    });
  });
  
  // User activity ping
  socket.on('activityPing', async () => {
    if (socket.userId) {
      const userData = onlineUsers.get(socket.userId);
      if (userData) {
        userData.lastActive = Date.now();
        onlineUsers.set(socket.userId, userData);
        
        const now = Date.now();
        if (!userData.lastDbUpdate || (now - userData.lastDbUpdate) > 60000) {
          await User.findByIdAndUpdate(socket.userId, {
            lastActive: now
          });
          userData.lastDbUpdate = now;
          onlineUsers.set(socket.userId, userData);
        }
      }
    }
  });
  
  // Disconnect handler
  socket.on('disconnect', async () => {
    console.log('🔌 Client disconnected:', socket.id);
    
    const userId = userSockets.get(socket.id);
    if (!userId) return;

    const { becameOffline } = removeUserSocket(userId, socket.id);

    if (becameOffline) {
      await User.findByIdAndUpdate(userId, {
        isOnline: false,
        lastSeen: Date.now(),
        socketId: ''
      });

      console.log('👤 User marked as offline:', userId);

      // Presence broadcast: show OFFLINE to everyone (requirement)
      io.emit('userOffline', { userId, timestamp: Date.now() });
    }
  });
  
  // Error handler
  socket.on('error', (error) => {
    console.error('❌ Socket error:', error);
  });
});

// ==================== ROUTES ====================

// Register User
app.post('/api/register', async (req, res) => {
  try {
    const { fullName, nickname, username, bio, university, studyGroup, phone, email, password } = req.body;
    
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    const existingPhone = await User.findOne({ phone });
    if (existingPhone) {
      return res.status(400).json({ error: 'Phone number already registered' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({
      fullName,
      nickname,
      username,
      bio,
      university,
      studyGroup,
      phone,
      email,
      password: hashedPassword
    });
    
    await user.save();
    
    await Stats.findOneAndUpdate({}, { $inc: { totalUsers: 1 } });
    
    const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '30d' });
    
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        nickname: user.nickname,
        avatar: user.avatar,
        university: user.university,
        isOnline: false
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login User
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    user.isOnline = true;
    user.lastSeen = Date.now();
    user.lastActive = Date.now();
    await user.save();
    
    const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '30d' });
    
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        nickname: user.nickname,
        avatar: user.avatar,
        university: user.university,
        isOnline: true
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Logout
app.post('/api/logout', authenticateToken, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.userId, { 
      isOnline: false, 
      lastSeen: Date.now(),
      lastActive: Date.now()
    });
    
    const socketId = getUserSocketId(req.userId);
    if (socketId) {
      onlineUsers.delete(req.userId);
      userSockets.delete(socketId);
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Get Current User
app.get('/api/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ success: true, user });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to get user' });
  }
});

// Update Profile
app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const updates = req.body;
    const user = await User.findById(req.userId);
    
    if (updates.username && updates.username !== user.username) {
      const fifteenDaysAgo = new Date(Date.now() - 15 * 24 * 60 * 60 * 1000);
      if (user.lastUsernameChange && user.lastUsernameChange > fifteenDaysAgo) {
        return res.status(400).json({ 
          error: 'Username can only be changed once every 15 days',
          nextChange: new Date(user.lastUsernameChange.getTime() + 15 * 24 * 60 * 60 * 1000)
        });
      }
      updates.lastUsernameChange = Date.now();
    }
    
    const updatedUser = await User.findByIdAndUpdate(
      req.userId,
      updates,
      { new: true, select: '-password' }
    );
    
    res.json({ success: true, user: updatedUser });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Profile update failed' });
  }
});

// Upload Avatar
app.post('/api/upload-avatar', authenticateToken, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const result = await cloudinary.uploader.upload(req.file.path, {
      folder: 'avatars',
      width: 300,
      height: 300,
      crop: 'fill'
    });
    
    const user = await User.findByIdAndUpdate(
      req.userId,
      { avatar: result.secure_url },
      { new: true, select: '-password' }
    );
    
    res.json({ success: true, avatar: user.avatar });
  } catch (error) {
    console.error('Upload avatar error:', error);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Search Users
app.get('/api/search/users', authenticateToken, async (req, res) => {
  try {
    const { query } = req.query;
    const users = await User.find({
      $or: [
        { username: { $regex: query, $options: 'i' } },
        { nickname: { $regex: query, $options: 'i' } },
        { fullName: { $regex: query, $options: 'i' } },
        { university: { $regex: query, $options: 'i' } }
      ],
      _id: { $ne: req.userId }
    })
    .select('username nickname avatar university isOnline lastSeen')
    .limit(20);
    
    res.json({ success: true, users });
  } catch (error) {
    console.error('Search users error:', error);
    res.status(500).json({ error: 'Search failed' });
  }
});

// Get User by ID
app.get('/api/user/:userId', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ success: true, user });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to get user' });
  }
});

// Get Conversations
app.get('/api/conversations', authenticateToken, async (req, res) => {
  try {
    // NOTE: In newer bson/mongoose versions, ObjectId is a class and must be instantiated with `new`.
    const me = new mongoose.Types.ObjectId(req.userId);
    const conversations = await Message.aggregate([
      {
        $match: {
          $or: [
            { senderId: me },
            { receiverId: me }
          ]
        }
      },
      {
        $sort: { createdAt: -1 }
      },
      {
        $group: {
          _id: {
            $cond: {
              if: { $eq: ["$senderId", me] },
              then: "$receiverId",
              else: "$senderId"
            }
          },
          lastMessage: { $first: "$$ROOT" },
          unreadCount: {
            $sum: {
              $cond: [
                { 
                  $and: [
                    { $ne: ["$senderId", me] },
                    { $eq: ["$isRead", false] }
                  ]
                },
                1,
                0
              ]
            }
          }
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'user'
        }
      },
      {
        $unwind: '$user'
      },
      {
        $project: {
          userId: '$_id',
          username: '$user.username',
          nickname: '$user.nickname',
          avatar: '$user.avatar',
          university: '$user.university',
          isOnline: '$user.isOnline',
          lastSeen: '$user.lastSeen',
          lastMessage: {
            text: '$lastMessage.text',
            mediaType: '$lastMessage.mediaType',
            createdAt: '$lastMessage.createdAt'
          },
          unreadCount: 1
        }
      },
      {
        $sort: { 'lastMessage.createdAt': -1 }
      }
    ]);
    
    res.json({ success: true, conversations });
  } catch (error) {
    console.error('Get conversations error:', error);
    res.status(500).json({ error: 'Failed to get conversations' });
  }
});

// Get Messages with a user
app.get('/api/messages/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 50 } = req.query;
    const skip = (page - 1) * limit;
    
    const messages = await Message.find({
      $or: [
        { senderId: req.userId, receiverId: userId },
        { senderId: userId, receiverId: req.userId }
      ]
    })
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(parseInt(limit))
    .populate('senderId', 'username nickname avatar')
    .populate('receiverId', 'username nickname avatar');
    
    await Message.updateMany(
      { 
        senderId: userId, 
        receiverId: req.userId, 
        isRead: false 
      },
      { 
        isRead: true,
        isDelivered: true
      }
    );
    
    await Message.updateMany(
      { 
        senderId: req.userId, 
        receiverId: userId, 
        isDelivered: false 
      },
      { 
        isDelivered: true 
      }
    );
    
    res.json({ 
      success: true, 
      messages: messages.reverse(),
      page: parseInt(page),
      limit: parseInt(limit)
    });
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Failed to get messages' });
  }
});

// Send Message
app.post('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { receiverId, text, mediaUrl, mediaType, mediaMetadata } = req.body;
    
    const receiver = await User.findById(receiverId);
    if (!receiver) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const message = new Message({
      senderId: req.userId,
      receiverId,
      text,
      mediaUrl,
      mediaType,
      mediaMetadata,
      isDelivered: false,
      isRead: false
    });
    
    await message.save();
    
    await Stats.findOneAndUpdate({}, { $inc: { totalMessages: 1 } });
    
    const populatedMessage = await Message.findById(message._id)
      .populate('senderId', 'username nickname avatar')
      .populate('receiverId', 'username nickname avatar');
    
    const receiverSocketId = getUserSocketId(receiverId);
    
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('newMessage', populatedMessage);
      message.isDelivered = true;
      await message.save();
    }
    
    const senderSocketId = getUserSocketId(req.userId);
    if (senderSocketId) {
      io.to(senderSocketId).emit('messageSent', populatedMessage);
    }
    
    res.json({ success: true, message: populatedMessage });
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Mark message as read
app.post('/api/messages/:messageId/read', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    
    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    if (!message.receiverId.equals(req.userId)) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    message.isRead = true;
    await message.save();
    
    const senderSocketId = getUserSocketId(message.senderId.toString());
    if (senderSocketId) {
      io.to(senderSocketId).emit('messageRead', {
        messageId: message._id,
        receiverId: req.userId,
        timestamp: Date.now()
      });
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Mark message read error:', error);
    res.status(500).json({ error: 'Failed to mark message as read' });
  }
});

// Mark messages as delivered
app.post('/api/messages/delivered', authenticateToken, async (req, res) => {
  try {
    const { messageIds } = req.body;
    
    await Message.updateMany(
      { _id: { $in: messageIds }, receiverId: req.userId },
      { isDelivered: true }
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Mark messages delivered error:', error);
    res.status(500).json({ error: 'Failed to mark messages as delivered' });
  }
});

// Voice message upload endpoint
app.post('/api/messages/voice', authenticateToken, upload.single('audio'), async (req, res) => {
  try {
    const { receiverId } = req.body;
    
    if (!req.file) {
      return res.status(400).json({ error: 'No audio file provided' });
    }
    
    const receiver = await User.findById(receiverId);
    if (!receiver) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const result = await cloudinary.uploader.upload(req.file.path, {
      resource_type: 'video',
      folder: 'voice_messages',
      format: 'webm',
      timeout: 120000
    });
    
    const duration = '0:00';
    
    const message = new Message({
      senderId: req.userId,
      receiverId,
      text: 'Voice message 🎤',
      mediaUrl: result.secure_url,
      mediaType: 'voice',
      mediaMetadata: {
        fileName: req.file.originalname,
        fileSize: req.file.size,
        mimeType: req.file.mimetype,
        duration: duration
      },
      isDelivered: false,
      isRead: false
    });
    
    await message.save();
    
    await Stats.findOneAndUpdate({}, { $inc: { totalMessages: 1 } });
    
    const populatedMessage = await Message.findById(message._id)
      .populate('senderId', 'username nickname avatar')
      .populate('receiverId', 'username nickname avatar');
    
    const receiverSocketId = getUserSocketId(receiverId);
    
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('newMessage', populatedMessage);
      message.isDelivered = true;
      await message.save();
    }
    
    const senderSocketId = getUserSocketId(req.userId);
    if (senderSocketId) {
      io.to(senderSocketId).emit('messageSent', populatedMessage);
    }
    
    const fs = require('fs');
    fs.unlinkSync(req.file.path);
    
    res.json({ success: true, message: populatedMessage });
  } catch (error) {
    console.error('Voice message upload error:', error);
    res.status(500).json({ error: 'Failed to send voice message' });
  }
});

// File upload endpoint
app.post('/api/messages/file', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    const { receiverId, text = '' } = req.body;
    
    if (!req.file) {
      return res.status(400).json({ error: 'No file provided' });
    }
    
    const receiver = await User.findById(receiverId);
    if (!receiver) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    let result;
    const mediaType = getMediaType(req.file.mimetype);
    
    if (req.file.mimetype.startsWith('image/')) {
      result = await cloudinary.uploader.upload(req.file.path, {
        folder: 'chat_images',
        quality: 'auto',
        fetch_format: 'auto'
      });
    } else if (req.file.mimetype.startsWith('video/')) {
      result = await cloudinary.uploader.upload(req.file.path, {
        resource_type: 'video',
        folder: 'chat_videos',
        chunk_size: 6000000
      });
    } else if (req.file.mimetype.startsWith('audio/')) {
      result = await cloudinary.uploader.upload(req.file.path, {
        resource_type: 'video',
        folder: 'chat_audio'
      });
    } else {
      result = await cloudinary.uploader.upload(req.file.path, {
        resource_type: 'raw',
        folder: 'chat_files'
      });
    }
    
    const message = new Message({
      senderId: req.userId,
      receiverId,
      text: text || `File: ${req.file.originalname}`,
      mediaUrl: result.secure_url,
      mediaType: mediaType,
      mediaMetadata: {
        fileName: req.file.originalname,
        fileSize: req.file.size,
        mimeType: req.file.mimetype,
        duration: mediaType === 'audio' || mediaType === 'voice' ? '0:00' : undefined
      },
      isDelivered: false,
      isRead: false
    });
    
    await message.save();
    
    await Stats.findOneAndUpdate({}, { $inc: { totalMessages: 1 } });
    
    const populatedMessage = await Message.findById(message._id)
      .populate('senderId', 'username nickname avatar')
      .populate('receiverId', 'username nickname avatar');
    
    const receiverSocketId = getUserSocketId(receiverId);
    
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('newMessage', populatedMessage);
      message.isDelivered = true;
      await message.save();
    }
    
    const senderSocketId = getUserSocketId(req.userId);
    if (senderSocketId) {
      io.to(senderSocketId).emit('messageSent', populatedMessage);
    }
    
    const fs = require('fs');
    fs.unlinkSync(req.file.path);
    
    res.json({ success: true, message: populatedMessage });
  } catch (error) {
    console.error('File upload error:', error);
    res.status(500).json({ error: 'Failed to send file' });
  }
});

// Get user's online status
app.get('/api/user/:userId/status', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const isOnline = onlineUsers.has(req.params.userId);
    
    res.json({
      success: true,
      isOnline,
      lastSeen: user.lastSeen,
      status: user.status
    });
  } catch (error) {
    console.error('Get user status error:', error);
    res.status(500).json({ error: 'Failed to get user status' });
  }
});

// Get online users
app.get('/api/users/online', authenticateToken, async (req, res) => {
  try {
    const onlineUserIds = Array.from(onlineUsers.keys());
    const users = await User.find({
      _id: { $in: onlineUserIds, $ne: req.userId }
    })
    .select('_id username nickname avatar university')
    .limit(50);
    
    res.json({ success: true, users });
  } catch (error) {
    console.error('Get online users error:', error);
    res.status(500).json({ error: 'Failed to get online users' });
  }
});

// Call History
app.get('/api/calls/history', authenticateToken, async (req, res) => {
  try {
    const calls = await CallHistory.find({
      $or: [
        { callerId: req.userId },
        { receiverId: req.userId }
      ]
    })
    .sort({ startedAt: -1 })
    .populate('callerId', 'username nickname avatar')
    .populate('receiverId', 'username nickname avatar')
    .limit(20);
    
    res.json({ success: true, calls });
  } catch (error) {
    console.error('Get call history error:', error);
    res.status(500).json({ error: 'Failed to get call history' });
  }
});

// Get call statistics
app.get('/api/calls/stats', authenticateToken, async (req, res) => {
  try {
    const me = new mongoose.Types.ObjectId(req.userId);
    const totalCalls = await CallHistory.countDocuments({
      $or: [
        { callerId: req.userId },
        { receiverId: req.userId }
      ]
    });
    
    const completedCalls = await CallHistory.countDocuments({
      $or: [
        { callerId: req.userId, status: 'completed' },
        { receiverId: req.userId, status: 'completed' }
      ]
    });
    
    const totalDuration = await CallHistory.aggregate([
      {
        $match: {
          $or: [
            { callerId: me },
            { receiverId: me }
          ],
          status: 'completed'
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: "$duration" }
        }
      }
    ]);
    
    res.json({
      success: true,
      stats: {
        totalCalls,
        completedCalls,
        totalDuration: totalDuration[0]?.total || 0
      }
    });
  } catch (error) {
    console.error('Get call stats error:', error);
    res.status(500).json({ error: 'Failed to get call statistics' });
  }
});

// Create Group
app.post('/api/groups', authenticateToken, async (req, res) => {
  try {
    const { name, username, description } = req.body;
    
    const group = new Group({
      name,
      username,
      description,
      creatorId: req.userId,
      members: [req.userId]
    });
    
    await group.save();
    
    await Stats.findOneAndUpdate({}, { $inc: { totalGroups: 1 } });
    
    res.json({ success: true, group });
  } catch (error) {
    console.error('Create group error:', error);
    res.status(500).json({ error: 'Failed to create group' });
  }
});

// Get User Groups
app.get('/api/groups', authenticateToken, async (req, res) => {
  try {
    const groups = await Group.find({ members: req.userId })
      .populate('creatorId', 'username nickname')
      .populate('members', 'username nickname avatar');
    
    res.json({ success: true, groups });
  } catch (error) {
    console.error('Get groups error:', error);
    res.status(500).json({ error: 'Failed to get groups' });
  }
});

// Get Group Messages
app.get('/api/groups/:groupId/messages', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const messages = await GroupMessage.find({ groupId })
      .sort({ createdAt: 1 })
      .populate('senderId', 'username nickname avatar');
    
    res.json({ success: true, messages });
  } catch (error) {
    console.error('Get group messages error:', error);
    res.status(500).json({ error: 'Failed to get group messages' });
  }
});

// Send Group Message
app.post('/api/groups/:groupId/messages', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const { text, mediaUrl, mediaType } = req.body;
    
    const group = await Group.findById(groupId);
    if (!group.members.includes(req.userId)) {
      return res.status(403).json({ error: 'Not a group member' });
    }
    
    const message = new GroupMessage({
      groupId,
      senderId: req.userId,
      text,
      mediaUrl,
      mediaType
    });
    
    await message.save();
    
    const populatedMessage = await GroupMessage.findById(message._id)
      .populate('senderId', 'username nickname avatar');
    
    io.to(`group_${groupId}`).emit('newGroupMessage', populatedMessage);
    
    res.json({ success: true, message: populatedMessage });
  } catch (error) {
    console.error('Send group message error:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Create Channel
app.post('/api/channels', authenticateToken, async (req, res) => {
  try {
    const { name, username, description, category, university, isPublic } = req.body;
    
    const existingChannel = await Channel.findOne({ username });
    if (existingChannel) {
      return res.status(400).json({ error: 'Channel username already exists' });
    }
    
    const channel = new Channel({
      name,
      username,
      description,
      category: category || 'other',
      university: university || '',
      isPublic: isPublic !== false,
      creatorId: req.userId,
      moderators: [req.userId],
      subscribers: [req.userId],
      inviteLink: uuidv4()
    });
    
    await channel.save();
    
    await Stats.findOneAndUpdate({}, { 
      $inc: { totalChannels: 1 } 
    });
    
    res.json({ 
      success: true, 
      channel: {
        ...channel.toObject(),
        isSubscribed: true,
        subscriberCount: 1,
        postCount: 0
      }
    });
  } catch (error) {
    console.error('Create channel error:', error);
    res.status(500).json({ error: 'Failed to create channel' });
  }
});

// Get Channel Posts
app.get('/api/channels/:channelId/posts', authenticateToken, async (req, res) => {
  try {
    const { channelId } = req.params;
    const posts = await ChannelPost.find({ channelId })
      .sort({ createdAt: -1 })
      .populate('channelId', 'name username');
    
    res.json({ success: true, posts });
  } catch (error) {
    console.error('Get channel posts error:', error);
    res.status(500).json({ error: 'Failed to get channel posts' });
  }
});

// Create Channel Post
app.post('/api/channels/:channelId/posts', authenticateToken, async (req, res) => {
  try {
    const { channelId } = req.params;
    const { content, mediaUrl, mediaType, type } = req.body;
    
    const channel = await Channel.findById(channelId);
    if (!channel) {
      return res.status(404).json({ error: 'Channel not found' });
    }
    
    const isCreator = channel.creatorId.equals(req.userId);
    const isModerator = channel.moderators.some(mod => mod.equals(req.userId));
    
    if (!isCreator && !isModerator) {
      return res.status(403).json({ error: 'Only channel admins can post' });
    }
    
    const post = new ChannelPost({
      channelId,
      content,
      mediaUrl,
      mediaType,
      type: type || 'announcement'
    });
    
    await post.save();
    
    io.to(`channel_${channelId}`).emit('newPost', {
      ...post.toObject(),
      channelId: {
        _id: channel._id,
        name: channel.name,
        username: channel.username
      }
    });
    
    res.json({ success: true, post });
  } catch (error) {
    console.error('Create channel post error:', error);
    res.status(500).json({ error: 'Failed to create post' });
  }
});

// Get Stats
app.get('/api/stats', async (req, res) => {
  try {
    const stats = await Stats.findOne();
    
    if (req.query.increment === 'true') {
      await Stats.findOneAndUpdate({}, { $inc: { dailyVisits: 1 } });
      const updatedStats = await Stats.findOne();
      return res.json({ success: true, stats: updatedStats });
    }
    
    res.json({ success: true, stats: stats || {} });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

// Get detailed statistics
app.get('/api/stats/detailed', authenticateToken, async (req, res) => {
  try {
    const stats = await Stats.findOne();
    
    const activeUsers = await User.countDocuments({ isOnline: true });
    
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayMessages = await Message.countDocuments({ createdAt: { $gte: today } });
    
    const todayGroups = await Group.countDocuments({ createdAt: { $gte: today } });
    
    const todayChannels = await Channel.countDocuments({ createdAt: { $gte: today } });
    
    const universityStats = await User.aggregate([
      { $group: { _id: '$university', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    
    res.json({
      success: true,
      stats: {
        ...stats.toObject(),
        activeUsers,
        todayMessages,
        todayGroups,
        todayChannels,
        universityStats: universityStats.map(u => ({
          name: u._id || 'Not specified',
          count: u.count
        }))
      }
    });
  } catch (error) {
    console.error('Get detailed stats error:', error);
    res.status(500).json({ error: 'Failed to get detailed stats' });
  }
});

// Join group
app.post('/api/groups/:groupId/join', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    
    const group = await Group.findById(groupId);
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    
    if (group.members.includes(req.userId)) {
      return res.status(400).json({ error: 'Already a member' });
    }
    
    group.members.push(req.userId);
    await group.save();
    
    res.json({ success: true, group });
  } catch (error) {
    console.error('Join group error:', error);
    res.status(500).json({ error: 'Failed to join group' });
  }
});

// Leave group
app.post('/api/groups/:groupId/leave', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    
    const group = await Group.findById(groupId);
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    
    if (group.creatorId.equals(req.userId)) {
      return res.status(400).json({ error: 'Group creator cannot leave. Transfer ownership first.' });
    }
    
    group.members = group.members.filter(memberId => !memberId.equals(req.userId));
    await group.save();
    
    res.json({ success: true });
  } catch (error) {
    console.error('Leave group error:', error);
    res.status(500).json({ error: 'Failed to leave group' });
  }
});

// Subscribe to channel
app.post('/api/channels/:channelId/subscribe', authenticateToken, async (req, res) => {
  try {
    const { channelId } = req.params;
    
    const channel = await Channel.findById(channelId);
    if (!channel) {
      return res.status(404).json({ error: 'Channel not found' });
    }
    
    if (channel.subscribers.includes(req.userId)) {
      return res.status(400).json({ error: 'Already subscribed' });
    }
    
    channel.subscribers.push(req.userId);
    await channel.save();
    
    io.to(`channel_${channelId}`).emit('channelSubscriptionUpdate', {
      channelId,
      action: 'subscribe',
      userId: req.userId
    });
    
    res.json({ success: true, channel });
  } catch (error) {
    console.error('Subscribe to channel error:', error);
    res.status(500).json({ error: 'Failed to subscribe' });
  }
});

// Unsubscribe from channel
app.post('/api/channels/:channelId/unsubscribe', authenticateToken, async (req, res) => {
  try {
    const { channelId } = req.params;
    
    const channel = await Channel.findById(channelId);
    if (!channel) {
      return res.status(404).json({ error: 'Channel not found' });
    }
    
    channel.subscribers = channel.subscribers.filter(subId => !subId.equals(req.userId));
    await channel.save();
    
    io.to(`channel_${channelId}`).emit('channelSubscriptionUpdate', {
      channelId,
      action: 'unsubscribe',
      userId: req.userId
    });
    
    res.json({ success: true });
  } catch (error) {
    console.error('Unsubscribe from channel error:', error);
    res.status(500).json({ error: 'Failed to unsubscribe' });
  }
});

// Get user's groups
app.get('/api/groups/my', authenticateToken, async (req, res) => {
  try {
    const groups = await Group.find({ creatorId: req.userId })
      .populate('members', 'username nickname avatar')
      .populate('creatorId', 'username nickname');
    
    res.json({ 
      success: true, 
      groups,
      stats: {
        myGroups: groups.length,
        totalMembers: groups.reduce((sum, group) => sum + group.members.length, 0)
      }
    });
  } catch (error) {
    console.error('Get user groups error:', error);
    res.status(500).json({ error: 'Failed to get groups' });
  }
});

// Get joined groups
app.get('/api/groups/joined', authenticateToken, async (req, res) => {
  try {
    const groups = await Group.find({ 
      members: req.userId,
      creatorId: { $ne: req.userId }
    })
    .populate('members', 'username nickname avatar')
    .populate('creatorId', 'username nickname');
    
    const totalGroups = await Group.countDocuments();
    
    res.json({ 
      success: true, 
      groups,
      stats: {
        joinedGroups: groups.length,
        totalGroups
      }
    });
  } catch (error) {
    console.error('Get joined groups error:', error);
    res.status(500).json({ error: 'Failed to get groups' });
  }
});

// Search Messages
app.get('/api/search/messages', authenticateToken, async (req, res) => {
  try {
    const { query } = req.query;
    const messages = await Message.find({
      text: { $regex: query, $options: 'i' },
      $or: [
        { senderId: req.userId },
        { receiverId: req.userId }
      ]
    })
    .populate('senderId', 'username nickname avatar')
    .populate('receiverId', 'username nickname avatar')
    .limit(20);
    
    res.json({ success: true, messages });
  } catch (error) {
    console.error('Search messages error:', error);
    res.status(500).json({ error: 'Search failed' });
  }
});

// Search Groups
app.get('/api/search/groups', authenticateToken, async (req, res) => {
  try {
    const { query } = req.query;
    const groups = await Group.find({
      $or: [
        { name: { $regex: query, $options: 'i' } },
        { username: { $regex: query, $options: 'i' } },
        { description: { $regex: query, $options: 'i' } }
      ]
    }).populate('creatorId', 'username nickname').limit(20);
    
    res.json({ success: true, groups });
  } catch (error) {
    console.error('Search groups error:', error);
    res.status(500).json({ error: 'Search failed' });
  }
});

// Search Channels
app.get('/api/search/channels', authenticateToken, async (req, res) => {
  try {
    const { query } = req.query;
    const channels = await Channel.find({
      $or: [
        { name: { $regex: query, $options: 'i' } },
        { username: { $regex: query, $options: 'i' } },
        { description: { $regex: query, $options: 'i' } }
      ]
    }).populate('creatorId', 'username nickname').limit(20);
    
    res.json({ success: true, channels });
  } catch (error) {
    console.error('Search channels error:', error);
    res.status(500).json({ error: 'Search failed' });
  }
});

// Get all public groups
app.get('/api/groups/all', authenticateToken, async (req, res) => {
  try {
    const groups = await Group.find()
      .populate('members', 'username nickname avatar')
      .populate('creatorId', 'username nickname')
      .limit(50);
    
    const totalGroups = await Group.countDocuments();
    const totalMembers = await Group.aggregate([
      { $project: { memberCount: { $size: "$members" } } },
      { $group: { _id: null, total: { $sum: "$memberCount" } } }
    ]);
    
    res.json({ 
      success: true, 
      groups,
      stats: {
        totalGroups,
        totalMembers: totalMembers[0]?.total || 0
      }
    });
  } catch (error) {
    console.error('Get all groups error:', error);
    res.status(500).json({ error: 'Failed to get groups' });
  }
});

// Get group information
app.get('/api/groups/:groupId', authenticateToken, async (req, res) => {
  try {
    const group = await Group.findById(req.params.groupId)
      .populate('creatorId', 'username nickname avatar')
      .populate('members', 'username nickname avatar isOnline');
    
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    
    const isMember = group.members.some(member => member._id.equals(req.userId));
    if (!isMember && !group.isPublic) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    res.json({ success: true, group });
  } catch (error) {
    console.error('Get group error:', error);
    res.status(500).json({ error: 'Failed to get group' });
  }
});

// Invite user to group
app.post('/api/groups/:groupId/invite', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const { userId } = req.body;
    
    const group = await Group.findById(groupId);
    
    if (!group.creatorId.equals(req.userId)) {
      return res.status(403).json({ error: 'Only group creator can invite users' });
    }
    
    if (group.members.includes(userId)) {
      return res.status(400).json({ error: 'User already in group' });
    }
    
    group.members.push(userId);
    await group.save();
    
    const user = await User.findById(userId).select('username nickname avatar');
    io.to(`group_${groupId}`).emit('groupMemberUpdate', {
      groupId,
      action: 'add',
      user
    });
    
    res.json({ success: true, group });
  } catch (error) {
    console.error('Invite to group error:', error);
    res.status(500).json({ error: 'Failed to invite user' });
  }
});

// Delete group
app.delete('/api/groups/:groupId', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    
    const group = await Group.findById(groupId);
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    
    if (!group.creatorId.equals(req.userId)) {
      return res.status(403).json({ error: 'Only group creator can delete group' });
    }
    
    await GroupMessage.deleteMany({ groupId });
    
    await Group.findByIdAndDelete(groupId);
    
    await Stats.findOneAndUpdate({}, { $inc: { totalGroups: -1 } });
    
    res.json({ success: true });
  } catch (error) {
    console.error('Delete group error:', error);
    res.status(500).json({ error: 'Failed to delete group' });
  }
});

// Profile stats
app.get('/api/profile/stats', authenticateToken, async (req, res) => {
  try {
    const friendsCount = await User.countDocuments({
      _id: { $ne: req.userId }
    });
    
    const groupsCount = await Group.countDocuments({
      members: req.userId
    });
    
    const messagesCount = await Message.countDocuments({
      $or: [
        { senderId: req.userId },
        { receiverId: req.userId }
      ]
    });
    
    res.json({
      success: true,
      stats: {
        friends: friendsCount,
        groups: groupsCount,
        messages: messagesCount
      }
    });
  } catch (error) {
    console.error('Get profile stats error:', error);
    res.status(500).json({ error: 'Failed to get profile stats' });
  }
});

// Profile activity
app.get('/api/profile/activity', authenticateToken, async (req, res) => {
  try {
    const recentMessages = await Message.find({
      $or: [
        { senderId: req.userId },
        { receiverId: req.userId }
      ]
    })
    .sort({ createdAt: -1 })
    .limit(10)
    .populate('senderId', 'nickname avatar')
    .populate('receiverId', 'nickname avatar');
    
    const activity = recentMessages.map(msg => ({
      type: 'message',
      icon: 'comment',
      description: `${msg.senderId.nickname} sent a message to ${msg.receiverId.nickname}`,
      timestamp: msg.createdAt
    }));
    
    const totalMessages = await Message.countDocuments({
      $or: [
        { senderId: req.userId },
        { receiverId: req.userId }
      ]
    });
    
    const me = new mongoose.Types.ObjectId(req.userId);
    const activeDays = await Message.aggregate([
      {
        $match: {
          $or: [
            { senderId: me },
            { receiverId: me }
          ]
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$createdAt" }
          }
        }
      },
      {
        $count: "days"
      }
    ]);
    
    res.json({
      success: true,
      activity: {
        recent: activity,
        totalMessages: totalMessages,
        activeDays: activeDays[0]?.days || 0,
        avgMessages: Math.round(totalMessages / 30)
      }
    });
  } catch (error) {
    console.error('Get profile activity error:', error);
    res.status(500).json({ error: 'Failed to get activity' });
  }
});

// Get channel by ID
app.get('/api/channels/:channelId', authenticateToken, async (req, res) => {
  try {
    const channel = await Channel.findById(req.params.channelId)
      .populate('creatorId', 'username nickname avatar')
      .populate('moderators', 'username nickname avatar')
      .populate('subscribers', 'username nickname avatar');
    
    if (!channel) {
      return res.status(404).json({ error: 'Channel not found' });
    }
    
    const isSubscribed = channel.subscribers.some(sub => 
      sub._id.equals(req.userId)
    );
    
    const postCount = await ChannelPost.countDocuments({ channelId: channel._id });
    
    const totalViews = await ChannelPost.aggregate([
      { $match: { channelId: channel._id } },
      { $group: { _id: null, total: { $sum: "$viewsCount" } } }
    ]);
    
    res.json({
      success: true,
      channel: {
        ...channel.toObject(),
        isSubscribed,
        postCount,
        totalViews: totalViews[0]?.total || 0,
        subscriberCount: channel.subscribers.length
      }
    });
  } catch (error) {
    console.error('Get channel error:', error);
    res.status(500).json({ error: 'Failed to get channel' });
  }
});

// Get paginated channel posts
app.get('/api/channels/:channelId/posts', authenticateToken, async (req, res) => {
  try {
    const { channelId } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const posts = await ChannelPost.find({ channelId })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .populate('channelId', 'name username');
    
    const totalPosts = await ChannelPost.countDocuments({ channelId });
    
    res.json({
      success: true,
      posts,
      hasMore: skip + posts.length < totalPosts,
      total: totalPosts
    });
  } catch (error) {
    console.error('Get channel posts error:', error);
    res.status(500).json({ error: 'Failed to get posts' });
  }
});

// Get channel subscribers
app.get('/api/channels/:channelId/subscribers', authenticateToken, async (req, res) => {
  try {
    const { channelId } = req.params;
    
    const channel = await Channel.findById(channelId)
      .populate('subscribers', 'username nickname avatar isOnline');
    
    if (!channel) {
      return res.status(404).json({ error: 'Channel not found' });
    }
    
    res.json({
      success: true,
      subscribers: channel.subscribers
    });
  } catch (error) {
    console.error('Get channel subscribers error:', error);
    res.status(500).json({ error: 'Failed to get subscribers' });
  }
});

// Get post by ID
app.get('/api/posts/:postId', authenticateToken, async (req, res) => {
  try {
    const post = await ChannelPost.findById(req.params.postId)
      .populate('channelId', 'name username');
    
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }
    res.json({ success: true, post });
  } catch (error) {
    console.error('Get post error:', error);
    res.status(500).json({ error: 'Failed to get post' });
  }
});

// Like/Unlike post
app.post('/api/posts/:postId/like', authenticateToken, async (req, res) => {
  try {
    const { postId } = req.params;
    
    const post = await ChannelPost.findById(postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }
    
    const alreadyLiked = post.likes.includes(req.userId);
    
    if (alreadyLiked) {
      post.likes = post.likes.filter(userId => !userId.equals(req.userId));
    } else {
      post.likes.push(req.userId);
    }
    
    await post.save();
    
    res.json({
      success: true,
      liked: !alreadyLiked,
      likeCount: post.likes.length
    });
  } catch (error) {
    console.error('Like post error:', error);
    res.status(500).json({ error: 'Failed to like post' });
  }
});

// Get media messages
app.get('/api/messages/:userId/media', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    
    const mediaMessages = await Message.find({
      $or: [
        { senderId: req.userId, receiverId: userId },
        { senderId: userId, receiverId: req.userId }
      ],
      mediaUrl: { $ne: '' }
    })
    .select('mediaUrl mediaType createdAt')
    .sort({ createdAt: -1 })
    .limit(50);
    
    res.json({
      success: true,
      media: mediaMessages
    });
  } catch (error) {
    console.error('Get media messages error:', error);
    res.status(500).json({ error: 'Failed to get media' });
  }
});

// Get channels
app.get('/api/channels', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 12;
    const skip = (page - 1) * limit;
    
    const query = {};
    
    if (req.query.category && req.query.category !== 'all') {
      query.category = req.query.category;
    }
    
    if (req.query.university) {
      query.university = req.query.university;
    }
    
    if (req.query.search) {
      query.$or = [
        { name: { $regex: req.query.search, $options: 'i' } },
        { description: { $regex: req.query.search, $options: 'i' } },
        { username: { $regex: req.query.search, $options: 'i' } }
      ];
    }
    
    let sort = { createdAt: -1 };
    if (req.query.sort === 'popular') {
      sort = { subscribers: -1 };
    }
    
    const channels = await Channel.find(query)
      .populate('creatorId', 'username nickname avatar')
      .sort(sort)
      .skip(skip)
      .limit(limit);
    
    const channelsWithSubscription = await Promise.all(
      channels.map(async (channel) => {
        const isSubscribed = channel.subscribers.some(subId => 
          subId.equals(req.userId)
        );
        
        const recentPosts = await ChannelPost.find({ channelId: channel._id })
          .sort({ createdAt: -1 })
          .limit(2)
          .select('content');
        
        return {
          ...channel.toObject(),
          isSubscribed,
          subscriberCount: channel.subscribers.length,
          postCount: await ChannelPost.countDocuments({ channelId: channel._id }),
          recentPosts
        };
      })
    );
    
    const totalChannels = await Channel.countDocuments(query);
    
    res.json({
      success: true,
      channels: channelsWithSubscription,
      hasMore: skip + channels.length < totalChannels,
      total: totalChannels
    });
  } catch (error) {
    console.error('Get channels error:', error);
    res.status(500).json({ error: 'Failed to get channels' });
  }
});

// Get channel stats
app.get('/api/channels/stats', authenticateToken, async (req, res) => {
  try {
    const totalChannels = await Channel.countDocuments();
    
    const channels = await Channel.find({});
    let totalSubscribers = 0;
    channels.forEach(channel => {
      totalSubscribers += channel.subscribers.length;
    });
    
    const myChannels = await Channel.countDocuments({ creatorId: req.userId });
    
    const subscribedChannels = await Channel.countDocuments({ 
      subscribers: req.userId 
    });
    
    res.json({
      success: true,
      stats: {
        totalChannels,
        totalSubscribers,
        myChannels,
        subscribedChannels
      }
    });
  } catch (error) {
    console.error('Get channel stats error:', error);
    res.status(500).json({ error: 'Failed to get channel stats' });
  }
});

// Get featured channels
app.get('/api/channels/featured', authenticateToken, async (req, res) => {
  try {
    const channels = await Channel.aggregate([
      {
        $addFields: {
          subscriberCount: { $size: "$subscribers" }
        }
      },
      { $sort: { subscriberCount: -1 } },
      { $limit: 3 },
      {
        $lookup: {
          from: 'users',
          localField: 'creatorId',
          foreignField: '_id',
          as: 'creatorId'
        }
      },
      { $unwind: '$creatorId' }
    ]);
    
    res.json({
      success: true,
      channels
    });
  } catch (error) {
    console.error('Get featured channels error:', error);
    res.status(500).json({ error: 'Failed to get featured channels' });
  }
});

// Get university statistics
app.get('/api/stats/universities', authenticateToken, async (req, res) => {
  try {
    const universities = await User.aggregate([
      { $group: { _id: '$university', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 20 }
    ]);
    
    res.json({
      success: true,
      universities: universities.map(u => ({
        name: u._id || 'Not specified',
        count: u.count
      }))
    });
  } catch (error) {
    console.error('Get university stats error:', error);
    res.status(500).json({ error: 'Failed to get university stats' });
  }
});

// Save/unsave post
app.post('/api/posts/:postId/save', authenticateToken, async (req, res) => {
  try {
    const { postId } = req.params;
    
    const post = await ChannelPost.findById(postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }
    
    const saved = Math.random() > 0.5;
    
    res.json({
      success: true,
      saved,
      message: saved ? 'Post saved' : 'Post removed from saved'
    });
  } catch (error) {
    console.error('Save post error:', error);
    res.status(500).json({ error: 'Failed to save post' });
  }
});

// Increment Post Views
app.post('/api/posts/:postId/view', authenticateToken, async (req, res) => {
  try {
    const { postId } = req.params;
    await ChannelPost.findByIdAndUpdate(postId, { $inc: { viewsCount: 1 } });
    res.json({ success: true });
  } catch (error) {
    console.error('Increment post views error:', error);
    res.status(500).json({ error: 'Failed to increment views' });
  }
});

// Get post comments
app.get('/api/posts/:postId/comments', authenticateToken, async (req, res) => {
  try {
    res.json({
      success: true,
      comments: []
    });
  } catch (error) {
    console.error('Get post comments error:', error);
    res.status(500).json({ error: 'Failed to get comments' });
  }
});

// Cloudinary upload endpoint
app.post('/api/upload', authenticateToken, async (req, res) => {
  try {
    const { fileUrl, fileType } = req.body;
    
    res.json({ 
      success: true, 
      url: fileUrl,
      type: fileType || 'image'
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Update user's online status
app.post('/api/user/status', authenticateToken, async (req, res) => {
  try {
    const { isOnline } = req.body;
    
    await User.findByIdAndUpdate(req.userId, { 
      isOnline: isOnline,
      lastSeen: Date.now()
    });
    
    const socketId = getUserSocketId(req.userId);
    if (socketId) {
      io.emit('userOnline', req.userId);
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Update user status error:', error);
    res.status(500).json({ error: 'Failed to update status' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is running',
    timestamp: Date.now(),
    onlineUsers: onlineUsers.size,
    connectedSockets: io.engine.clientsCount
  });
});

// Get server stats
app.get('/api/server/stats', authenticateToken, async (req, res) => {
  try {
    const stats = await Stats.findOne();
    
    res.json({
      success: true,
      stats: {
        ...stats.toObject(),
        onlineUsers: onlineUsers.size,
        connectedSockets: io.engine.clientsCount,
        uptime: process.uptime()
      }
    });
  } catch (error) {
    console.error('Get server stats error:', error);
    res.status(500).json({ error: 'Failed to get server stats' });
  }
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 3000;

const fs = require('fs');
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads', { recursive: true });
}

server.listen(PORT, async () => {
  await initializeStats();
  
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📊 MongoDB: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'}`);
  
  setInterval(async () => {
    const now = new Date();
    if (now.getHours() === 0 && now.getMinutes() === 0) {
      await Stats.findOneAndUpdate({}, { dailyVisits: 0 });
      console.log('📊 Daily stats reset');
    }
  }, 60000);
  
  setInterval(() => {
    const dir = 'uploads';
    if (fs.existsSync(dir)) {
      fs.readdir(dir, (err, files) => {
        if (err) return;
        
        files.forEach(file => {
          const filePath = path.join(dir, file);
          fs.stat(filePath, (err, stat) => {
            if (err) return;
            
            if (Date.now() - stat.mtimeMs > 3600000) {
              fs.unlinkSync(filePath);
            }
          });
        });
      });
    }
  }, 3600000);
});