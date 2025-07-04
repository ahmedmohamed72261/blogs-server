const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const Blog = require('../models/Blog');
const { auth, adminAuth, ownerOrAdmin, secureAdminAuth } = require('../middleware/auth');
const { upload, uploadToCloudinary, deleteFromCloudinary } = require('../config/cloudinary');

const router = express.Router();

// @route   GET /api/users/profile
// @desc    Get current user profile
// @access  Private
router.get('/profile', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    const blogCount = await Blog.countDocuments({ author: req.user._id });
    
    res.json({
      user,
      stats: {
        totalBlogs: blogCount,
        publishedBlogs: await Blog.countDocuments({ author: req.user._id, status: 'published' }),
        draftBlogs: await Blog.countDocuments({ author: req.user._id, status: 'draft' })
      }
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ message: 'Server error while fetching profile' });
  }
});

// @route   PUT /api/users/profile
// @desc    Update user profile
// @access  Private
router.put('/profile', [
  auth,
  upload.single('avatar'),
  body('firstName')
    .optional()
    .isLength({ max: 50 })
    .withMessage('First name cannot exceed 50 characters'),
  body('lastName')
    .optional()
    .isLength({ max: 50 })
    .withMessage('Last name cannot exceed 50 characters'),
  body('bio')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Bio cannot exceed 500 characters'),
  body('username')
    .optional()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3 and 30 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        message: 'Validation failed', 
        errors: errors.array() 
      });
    }

    const user = await User.findById(req.user._id);
    const { firstName, lastName, bio, username } = req.body;

    // Check if username is already taken (if being updated)
    if (username && username !== user.username) {
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        return res.status(400).json({ message: 'Username is already taken' });
      }
      user.username = username;
    }

    // Handle avatar upload
    if (req.file) {
      try {
        // Delete old avatar if exists
        if (user.avatar) {
          const publicId = user.avatar.split('/').pop().split('.')[0];
          await deleteFromCloudinary(`blog-dashboard/avatars/${publicId}`);
        }
        
        const uploadResult = await uploadToCloudinary(req.file.buffer, 'blog-dashboard/avatars');
        user.avatar = uploadResult.url;
      } catch (uploadError) {
        console.error('Avatar upload error:', uploadError);
        return res.status(400).json({ message: 'Failed to upload avatar' });
      }
    }

    // Update fields
    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;
    if (bio !== undefined) user.bio = bio;

    await user.save();

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        avatar: user.avatar,
        bio: user.bio,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ message: 'Server error while updating profile' });
  }
});

// @route   PUT /api/users/change-password
// @desc    Change user password
// @access  Private
router.put('/change-password', [
  auth,
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 6 })
    .withMessage('New password must be at least 6 characters long'),
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error('Password confirmation does not match');
      }
      return true;
    })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        message: 'Validation failed', 
        errors: errors.array() 
      });
    }

    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user._id);

    // Verify current password
    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) {
      return res.status(400).json({ message: 'Current password is incorrect' });
    }

    // Update password
    user.password = newPassword;
    await user.save();

    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ message: 'Server error while changing password' });
  }
});

// @route   GET /api/users
// @desc    Get all users (Admin only)
// @access  Private (Admin)
router.get('/', [auth, ...secureAdminAuth], async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const users = await User.find()
      .select('-password')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await User.countDocuments();

    res.json({
      users,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalUsers: total,
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Server error while fetching users' });
  }
});

// @route   GET /api/users/:id
// @desc    Get user by ID
// @access  Public
router.get('/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password -email');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const blogCount = await Blog.countDocuments({ 
      author: req.params.id, 
      status: 'published' 
    });

    res.json({
      user,
      stats: {
        publishedBlogs: blogCount
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    if (error.name === 'CastError') {
      return res.status(400).json({ message: 'Invalid user ID' });
    }
    res.status(500).json({ message: 'Server error while fetching user' });
  }
});

// @route   PUT /api/users/:id/status
// @desc    Update user status (Admin only)
// @access  Private (Admin)
router.put('/:id/status', [
  auth,
  ...secureAdminAuth,
  body('isActive')
    .isBoolean()
    .withMessage('isActive must be a boolean value')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        message: 'Validation failed', 
        errors: errors.array() 
      });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Prevent admin from deactivating themselves
    if (req.user._id.toString() === req.params.id) {
      return res.status(400).json({ message: 'You cannot deactivate your own account' });
    }

    user.isActive = req.body.isActive;
    await user.save();

    res.json({
      message: `User ${req.body.isActive ? 'activated' : 'deactivated'} successfully`,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isActive: user.isActive
      }
    });
  } catch (error) {
    console.error('Update user status error:', error);
    if (error.name === 'CastError') {
      return res.status(400).json({ message: 'Invalid user ID' });
    }
    res.status(500).json({ message: 'Server error while updating user status' });
  }
});

// @route   DELETE /api/users/:id
// @desc    Delete user account (Admin only)
// @access  Private (Admin)
router.delete('/:id', [auth, ...secureAdminAuth], async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Prevent admin from deleting themselves
    if (req.user._id.toString() === req.params.id) {
      return res.status(400).json({ message: 'You cannot delete your own account' });
    }

    // Delete user's blogs and associated images
    const userBlogs = await Blog.find({ author: req.params.id });
    for (const blog of userBlogs) {
      if (blog.featuredImage.publicId) {
        try {
          await deleteFromCloudinary(blog.featuredImage.publicId);
        } catch (deleteError) {
          console.error('Error deleting blog image:', deleteError);
        }
      }
    }
    await Blog.deleteMany({ author: req.params.id });

    // Delete user avatar
    if (user.avatar) {
      try {
        const publicId = user.avatar.split('/').pop().split('.')[0];
        await deleteFromCloudinary(`blog-dashboard/avatars/${publicId}`);
      } catch (deleteError) {
        console.error('Error deleting user avatar:', deleteError);
      }
    }

    await User.findByIdAndDelete(req.params.id);

    res.json({ message: 'User and all associated data deleted successfully' });
  } catch (error) {
    console.error('Delete user error:', error);
    if (error.name === 'CastError') {
      return res.status(400).json({ message: 'Invalid user ID' });
    }
    res.status(500).json({ message: 'Server error while deleting user' });
  }
});

module.exports = router;