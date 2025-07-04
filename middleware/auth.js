const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Verify JWT token
const auth = async (req, res, next) => {
  try {
    const authHeader = req.header('Authorization');
    
    if (!authHeader) {
      return res.status(401).json({ 
        message: 'Access denied. No authorization header provided.',
        code: 'NO_AUTH_HEADER'
      });
    }

    const token = authHeader.replace('Bearer ', '');
    
    if (!token || token === 'null' || token === 'undefined') {
      return res.status(401).json({ 
        message: 'Access denied. No valid token provided.',
        code: 'NO_TOKEN'
      });
    }

    // Verify JWT secret exists
    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET is not defined in environment variables');
      return res.status(500).json({ 
        message: 'Server configuration error',
        code: 'SERVER_CONFIG_ERROR'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    if (!decoded.userId) {
      return res.status(401).json({ 
        message: 'Invalid token structure',
        code: 'INVALID_TOKEN_STRUCTURE'
      });
    }

    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      return res.status(401).json({ 
        message: 'User not found. Token may be invalid or user may have been deleted.',
        code: 'USER_NOT_FOUND'
      });
    }

    if (!user.isActive) {
      return res.status(401).json({ 
        message: 'Account is deactivated. Please contact administrator.',
        code: 'ACCOUNT_DEACTIVATED'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    
    // Handle specific JWT errors
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        message: 'Invalid token format',
        code: 'INVALID_TOKEN_FORMAT'
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        message: 'Token has expired. Please login again.',
        code: 'TOKEN_EXPIRED'
      });
    }

    if (error.name === 'NotBeforeError') {
      return res.status(401).json({ 
        message: 'Token not active yet',
        code: 'TOKEN_NOT_ACTIVE'
      });
    }

    // Database connection errors
    if (error.name === 'MongooseError' || error.name === 'MongoError') {
      console.error('Database error in auth middleware:', error);
      return res.status(503).json({ 
        message: 'Database temporarily unavailable. Please try again later.',
        code: 'DATABASE_ERROR'
      });
    }

    // Generic error fallback
    return res.status(500).json({ 
      message: 'Authentication service temporarily unavailable',
      code: 'AUTH_SERVICE_ERROR'
    });
  }
};

// Check if user is admin
const adminAuth = (req, res, next) => {
  try {
    // Ensure user object exists (should be set by auth middleware)
    if (!req.user) {
      return res.status(401).json({ 
        message: 'Authentication required. Please login first.',
        code: 'AUTH_REQUIRED'
      });
    }

    // Check if user has admin role
    if (req.user.role !== 'admin') {
      console.warn(`Unauthorized admin access attempt by user: ${req.user.username} (${req.user._id})`);
      return res.status(403).json({ 
        message: 'Access denied. Administrator privileges required.',
        code: 'ADMIN_REQUIRED'
      });
    }

    // Verify admin account is still active
    if (!req.user.isActive) {
      return res.status(403).json({ 
        message: 'Admin account is deactivated.',
        code: 'ADMIN_DEACTIVATED'
      });
    }

    next();
  } catch (error) {
    console.error('Admin auth middleware error:', error);
    return res.status(500).json({ 
      message: 'Authorization service error',
      code: 'ADMIN_AUTH_ERROR'
    });
  }
};

// Check if user owns the resource or is admin
const ownerOrAdmin = (req, res, next) => {
  try {
    // Ensure user object exists
    if (!req.user) {
      return res.status(401).json({ 
        message: 'Authentication required. Please login first.',
        code: 'AUTH_REQUIRED'
      });
    }

    // Check if user is admin or owns the resource
    const isAdmin = req.user.role === 'admin';
    const isOwner = req.user._id.toString() === req.params.userId;

    if (!isAdmin && !isOwner) {
      console.warn(`Unauthorized resource access attempt by user: ${req.user.username} (${req.user._id}) for resource: ${req.params.userId}`);
      return res.status(403).json({ 
        message: 'Access denied. You can only access your own resources or must be an administrator.',
        code: 'RESOURCE_ACCESS_DENIED'
      });
    }

    // Verify account is still active
    if (!req.user.isActive) {
      return res.status(403).json({ 
        message: 'Account is deactivated.',
        code: 'ACCOUNT_DEACTIVATED'
      });
    }

    next();
  } catch (error) {
    console.error('Owner/Admin auth middleware error:', error);
    return res.status(500).json({ 
      message: 'Authorization service error',
      code: 'OWNER_ADMIN_AUTH_ERROR'
    });
  }
};

// Log admin activities for security monitoring
const logAdminActivity = (req, res, next) => {
  try {
    if (req.user && req.user.role === 'admin') {
      const activity = {
        adminId: req.user._id,
        adminUsername: req.user.username,
        action: `${req.method} ${req.originalUrl}`,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
        body: req.method !== 'GET' ? JSON.stringify(req.body) : null
      };
      
      console.log('🔐 ADMIN ACTIVITY:', JSON.stringify(activity, null, 2));
    }
    next();
  } catch (error) {
    console.error('Admin activity logging error:', error);
    // Don't block the request if logging fails
    next();
  }
};

// Enhanced admin auth that includes activity logging
const secureAdminAuth = [adminAuth, logAdminActivity];

module.exports = {
  auth,
  adminAuth,
  ownerOrAdmin,
  logAdminActivity,
  secureAdminAuth
};