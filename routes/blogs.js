const express = require('express');
const { body, validationResult, query } = require('express-validator');
const Blog = require('../models/Blog');
const { auth, adminAuth } = require('../middleware/auth');
const { upload, uploadToCloudinary, deleteFromCloudinary } = require('../config/cloudinary');

const router = express.Router();

// @route   GET /api/blogs
// @desc    Get all blogs with pagination and filtering
// @access  Public
router.get('/', [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 50 }).withMessage('Limit must be between 1 and 50'),
  query('status').optional().isIn(['draft', 'published', 'archived']).withMessage('Invalid status'),
  query('category').optional().isString().withMessage('Category must be a string'),
  query('author').optional().isMongoId().withMessage('Invalid author ID')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        message: 'Validation failed', 
        errors: errors.array() 
      });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Build filter object
    const filter = {};
    
    // Only show published blogs for non-authenticated users
    if (!req.user) {
      filter.status = 'published';
    } else if (req.query.status) {
      filter.status = req.query.status;
    }

    if (req.query.category) {
      filter.category = new RegExp(req.query.category, 'i');
    }

    if (req.query.author) {
      filter.author = req.query.author;
    }

    if (req.query.search) {
      filter.$or = [
        { title: new RegExp(req.query.search, 'i') },
        { content: new RegExp(req.query.search, 'i') },
        { tags: { $in: [new RegExp(req.query.search, 'i')] } }
      ];
    }

    // If user is not admin, only show their own drafts/archived posts
    if (req.user && req.user.role !== 'admin' && req.query.status && req.query.status !== 'published') {
      filter.author = req.user._id;
    }

    const blogs = await Blog.find(filter)
      .populate('author', 'username firstName lastName avatar')
      .sort({ publishedAt: -1, createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Blog.countDocuments(filter);

    res.json({
      blogs,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalBlogs: total,
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Get blogs error:', error);
    res.status(500).json({ message: 'Server error while fetching blogs' });
  }
});

// @route   GET /api/blogs/:id
// @desc    Get single blog by ID
// @access  Public
router.get('/:id', async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id)
      .populate('author', 'username firstName lastName avatar bio')
      .populate('comments.user', 'username firstName lastName avatar');

    if (!blog) {
      return res.status(404).json({ message: 'Blog not found' });
    }

    // Check if user can view this blog
    if (blog.status !== 'published' && (!req.user || (req.user._id.toString() !== blog.author._id.toString() && req.user.role !== 'admin'))) {
      return res.status(403).json({ message: 'Access denied' });
    }

    // Increment views for published blogs
    if (blog.status === 'published') {
      blog.views += 1;
      await blog.save();
    }

    res.json(blog);
  } catch (error) {
    console.error('Get blog error:', error);
    if (error.name === 'CastError') {
      return res.status(400).json({ message: 'Invalid blog ID' });
    }
    res.status(500).json({ message: 'Server error while fetching blog' });
  }
});

// @route   POST /api/blogs
// @desc    Create a new blog
// @access  Private
router.post('/', [
  auth,
  upload.single('featuredImage'),
  body('title')
    .notEmpty()
    .withMessage('Title is required')
    .isLength({ max: 200 })
    .withMessage('Title cannot exceed 200 characters'),
  body('content')
    .notEmpty()
    .withMessage('Content is required'),
  body('category')
    .notEmpty()
    .withMessage('Category is required'),
  body('excerpt')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Excerpt cannot exceed 500 characters'),
  body('tags')
    .optional()
    .custom((value, { req }) => {
      // Handle both array and string formats
      if (typeof value === 'string') {
        try {
          const parsed = JSON.parse(value);
          req.body.tags = Array.isArray(parsed) ? parsed : [];
          return true;
        } catch {
          // If not JSON, treat as comma-separated string
          req.body.tags = value.split(',').map(tag => tag.trim()).filter(tag => tag);
          return true;
        }
      } else if (Array.isArray(value)) {
        return true;
      } else if (value === undefined || value === null) {
        req.body.tags = [];
        return true;
      }
      throw new Error('Tags must be an array or comma-separated string');
    }),
  body('status')
    .optional()
    .isIn(['draft', 'published'])
    .withMessage('Status must be either draft or published')
], async (req, res) => {
  try {
    console.log('Create blog request body:', req.body);
    console.log('Create blog file:', req.file);
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('Validation errors:', errors.array());
      return res.status(400).json({ 
        message: 'Validation failed', 
        errors: errors.array() 
      });
    }

    const { title, content, category, excerpt, tags, status, seo } = req.body;

    // Generate slug from title
    const generateSlug = async (title) => {
      let baseSlug = title
        .toLowerCase()
        .replace(/[^a-zA-Z0-9 ]/g, '')
        .replace(/\s+/g, '-')
        .replace(/-+/g, '-')
        .replace(/^-+|-+$/g, ''); // Remove leading/trailing dashes
      
      // Ensure slug is unique
      let slug = baseSlug;
      let counter = 1;
      
      while (true) {
        const existingBlog = await Blog.findOne({ slug: slug });
        
        if (!existingBlog) {
          break;
        }
        
        slug = `${baseSlug}-${counter}`;
        counter++;
      }
      
      return slug;
    };

    // Handle featured image upload
    let featuredImage = { url: '', publicId: '' };
    if (req.file) {
      try {
        console.log('Uploading image to Cloudinary...');
        const uploadResult = await uploadToCloudinary(req.file.buffer, 'blog-images');
        console.log('Image upload successful:', uploadResult);
        featuredImage = uploadResult;
      } catch (uploadError) {
        console.error('Image upload error:', uploadError);
        return res.status(400).json({ message: 'Failed to upload image: ' + uploadError.message });
      }
    }

    // Generate unique slug
    const slug = await generateSlug(title);

    console.log('Creating blog with data:', {
      title,
      slug,
      content: content?.substring(0, 100) + '...',
      category,
      excerpt,
      tags: tags || [],
      status: status || 'draft',
      author: req.user._id,
      featuredImage
    });

    const blog = new Blog({
      title,
      slug,
      content,
      category,
      excerpt,
      tags: tags || [],
      status: status || 'draft',
      author: req.user._id,
      featuredImage,
      seo: seo || {}
    });

    console.log('Saving blog to database...');
    await blog.save();
    console.log('Blog saved successfully');
    
    await blog.populate('author', 'username firstName lastName avatar');

    res.status(201).json({
      message: 'Blog created successfully',
      blog
    });
  } catch (error) {
    console.error('Create blog error:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ 
      message: 'Server error while creating blog',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @route   PUT /api/blogs/:id
// @desc    Update a blog
// @access  Private (Owner or Admin)
router.put('/:id', [
  auth,
  upload.single('featuredImage'),
  body('title')
    .optional()
    .isLength({ max: 200 })
    .withMessage('Title cannot exceed 200 characters'),
  body('excerpt')
    .optional()
    .isLength({ max: 500 })
    .withMessage('Excerpt cannot exceed 500 characters'),
  body('tags')
    .optional()
    .custom((value, { req }) => {
      // Handle both array and string formats
      if (typeof value === 'string') {
        try {
          const parsed = JSON.parse(value);
          req.body.tags = Array.isArray(parsed) ? parsed : [];
          return true;
        } catch {
          // If not JSON, treat as comma-separated string
          req.body.tags = value.split(',').map(tag => tag.trim()).filter(tag => tag);
          return true;
        }
      } else if (Array.isArray(value)) {
        return true;
      } else if (value === undefined || value === null) {
        req.body.tags = [];
        return true;
      }
      throw new Error('Tags must be an array or comma-separated string');
    }),
  body('status')
    .optional()
    .isIn(['draft', 'published', 'archived'])
    .withMessage('Invalid status')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        message: 'Validation failed', 
        errors: errors.array() 
      });
    }

    const blog = await Blog.findById(req.params.id);
    if (!blog) {
      return res.status(404).json({ message: 'Blog not found' });
    }

    // Check if user owns the blog or is admin
    if (blog.author.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied. You can only edit your own blogs.' });
    }

    const { title, content, category, excerpt, tags, status, seo } = req.body;

    // Handle featured image upload
    if (req.file) {
      try {
        // Delete old image if exists
        if (blog.featuredImage.publicId) {
          await deleteFromCloudinary(blog.featuredImage.publicId);
        }
        
        const uploadResult = await uploadToCloudinary(req.file.buffer, 'blog-images');
        blog.featuredImage = uploadResult;
      } catch (uploadError) {
        console.error('Image upload error:', uploadError);
        return res.status(400).json({ message: 'Failed to upload image' });
      }
    }

    // Update fields
    if (title) blog.title = title;
    if (content) blog.content = content;
    if (category) blog.category = category;
    if (excerpt !== undefined) blog.excerpt = excerpt;
    if (tags) blog.tags = tags;
    if (status) blog.status = status;
    if (seo) blog.seo = { ...blog.seo, ...seo };

    await blog.save();
    await blog.populate('author', 'username firstName lastName avatar');

    res.json({
      message: 'Blog updated successfully',
      blog
    });
  } catch (error) {
    console.error('Update blog error:', error);
    if (error.name === 'CastError') {
      return res.status(400).json({ message: 'Invalid blog ID' });
    }
    res.status(500).json({ message: 'Server error while updating blog' });
  }
});

// @route   DELETE /api/blogs/:id
// @desc    Delete a blog
// @access  Private (Owner or Admin)
router.delete('/:id', auth, async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    if (!blog) {
      return res.status(404).json({ message: 'Blog not found' });
    }

    // Check if user owns the blog or is admin
    if (blog.author.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied. You can only delete your own blogs.' });
    }

    // Delete featured image from Cloudinary
    if (blog.featuredImage.publicId) {
      try {
        await deleteFromCloudinary(blog.featuredImage.publicId);
      } catch (deleteError) {
        console.error('Error deleting image from Cloudinary:', deleteError);
      }
    }

    await Blog.findByIdAndDelete(req.params.id);

    res.json({ message: 'Blog deleted successfully' });
  } catch (error) {
    console.error('Delete blog error:', error);
    if (error.name === 'CastError') {
      return res.status(400).json({ message: 'Invalid blog ID' });
    }
    res.status(500).json({ message: 'Server error while deleting blog' });
  }
});

// @route   POST /api/blogs/:id/like
// @desc    Like/Unlike a blog
// @access  Private
router.post('/:id/like', auth, async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    if (!blog) {
      return res.status(404).json({ message: 'Blog not found' });
    }

    const existingLike = blog.likes.find(like => like.user.toString() === req.user._id.toString());

    if (existingLike) {
      // Unlike
      blog.likes = blog.likes.filter(like => like.user.toString() !== req.user._id.toString());
    } else {
      // Like
      blog.likes.push({ user: req.user._id });
    }

    await blog.save();

    res.json({
      message: existingLike ? 'Blog unliked' : 'Blog liked',
      likesCount: blog.likes.length,
      isLiked: !existingLike
    });
  } catch (error) {
    console.error('Like blog error:', error);
    if (error.name === 'CastError') {
      return res.status(400).json({ message: 'Invalid blog ID' });
    }
    res.status(500).json({ message: 'Server error while liking blog' });
  }
});

// @route   POST /api/blogs/:id/comment
// @desc    Add a comment to a blog
// @access  Private
router.post('/:id/comment', [
  auth,
  body('content')
    .notEmpty()
    .withMessage('Comment content is required')
    .isLength({ max: 1000 })
    .withMessage('Comment cannot exceed 1000 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        message: 'Validation failed', 
        errors: errors.array() 
      });
    }

    const blog = await Blog.findById(req.params.id);
    if (!blog) {
      return res.status(404).json({ message: 'Blog not found' });
    }

    if (blog.status !== 'published') {
      return res.status(400).json({ message: 'Cannot comment on unpublished blogs' });
    }

    const comment = {
      user: req.user._id,
      content: req.body.content
    };

    blog.comments.push(comment);
    await blog.save();
    await blog.populate('comments.user', 'username firstName lastName avatar');

    res.status(201).json({
      message: 'Comment added successfully',
      comment: blog.comments[blog.comments.length - 1]
    });
  } catch (error) {
    console.error('Add comment error:', error);
    if (error.name === 'CastError') {
      return res.status(400).json({ message: 'Invalid blog ID' });
    }
    res.status(500).json({ message: 'Server error while adding comment' });
  }
});

module.exports = router;