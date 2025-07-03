const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const authRoutes = require('./routes/auth');
const blogRoutes = require('./routes/blogs');

const app = express();

// Security middleware
app.use(helmet());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Middleware
app.use(cors({
  origin: true, // Accept requests from any origin
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/blog-dashboard', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB connected successfully - Server deployed on Vercel!'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/blogs', blogRoutes);

// Health check endpoint with deployment message
app.get('/api/health', (req, res) => {
  res.json({ 
    message: '🚀 Blog Server is running successfully on Vercel!', 
    status: 'OK',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Welcome endpoint for deployment verification
app.get('/', (req, res) => {
  res.json({
    message: '🎉 Welcome to Blog Dashboard API!',
    status: 'Successfully deployed on Vercel',
    endpoints: {
      health: '/api/health',
      auth: '/api/auth',
      blogs: '/api/blogs'
    },
    documentation: 'API is ready to use!'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    message: 'Something went wrong!',
    error: process.env.NODE_ENV === 'production' ? {} : err.stack
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT} - Successfully deployed on Vercel!`);
});

module.exports = app;