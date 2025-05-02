const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const cloudinary = require('cloudinary').v2;
const fileUpload = require('express-fileupload');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));
app.use(fileUpload({ createParentPath: true }));

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Database connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: {
    rejectUnauthorized: false, // Required for Supabase on Render
  },
});

// JWT middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access token required' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
};

// Register route
app.post('/api/register', async (req, res) => {
  const { username, email, password, confirmPassword } = req.body;
  let profilePictureUrl = null;

  try {
    if (!username || !email || !password || !confirmPassword) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }

    const userCheck = await pool.query(
      'SELECT * FROM users WHERE email = $1 OR username = $2',
      [email, username]
    );
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Username or email already exists' });
    }

    if (req.files && req.files.profilePicture) {
      const file = req.files.profilePicture;
      if (!file.mimetype.startsWith('image/')) {
        return res.status(400).json({ message: 'Profile picture must be an image' });
      }
      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: 'mini-blog/avatars' },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        stream.end(file.data);
      });
      profilePictureUrl = result.secure_url;
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await pool.query(
      'INSERT INTO users (username, email, password, profile_picture, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING id, username, email, profile_picture',
      [username, email, hashedPassword, profilePictureUrl]
    );

    const token = jwt.sign({ id: newUser.rows[0].id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.status(201).json({ token, user: newUser.rows[0] });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const user = userResult.rows[0];

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.status(200).json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        profile_picture: user.profile_picture,
        cover_image: user.cover_image,
        theme_color: user.theme_color,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, email, profile_picture, cover_image, theme_color, created_at FROM users WHERE id = $1',
      [req.user.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Forgot password route
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }

    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(400).json({ message: 'Email not found' });
    }

    const user = userResult.rows[0];
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 3600000);

    await pool.query(
      'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [user.id, token, expiresAt]
    );

    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}&email=${email}`;
    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #1e40af;">Mini Blog Password Reset</h2>
        <p>Hello ${user.username},</p>
        <p>We received a request to reset your password. Click the button below to set a new password:</p>
        <a href="${resetLink}" style="display: inline-block; padding: 10px 20px; background-color: #1e40af; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">
          Reset Password
        </a>
        <p>This link will expire in 1 hour for security reasons.</p>
        <p>If you didn’t request this, please ignore this email.</p>
        <p>Best regards,<br>The Mini Blog Team</p>
        <hr style="border-top: 1px solid #e5e7eb; margin-top: 20px;">
        <p style="font-size: 12px; color: #6b7280;">Mini Blog © 2025</p>
      </div>
    `;

    await transporter.sendMail({
      from: `"Mini Blog" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Reset Your Mini Blog Password',
      text: `Hello ${user.username},\n\nClick this link to reset your password: ${resetLink}\n\nThis link will expire in 1 hour.\n\nIf you didn’t request this, ignore this email.\n\nBest,\nMini Blog Team`,
      html: htmlContent,
    });

    res.status(200).json({ message: 'Reset link sent to your email' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Reset password route
app.post('/api/reset-password', async (req, res) => {
  const { email, token, password, confirmPassword } = req.body;

  try {
    if (!email || !token || !password || !confirmPassword) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }

    const tokenResult = await pool.query(
      'SELECT * FROM password_reset_tokens WHERE token = $1 AND expires_at > NOW()',
      [token]
    );
    if (tokenResult.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(400).json({ message: 'User not found' });
    }

    const user = userResult.rows[0];
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, user.id]);
    await pool.query('DELETE FROM password_reset_tokens WHERE token = $1', [token]);

    res.status(200).json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user profile
app.get('/api/users/:id', authenticateToken, async (req, res) => {
  const userId = req.params.id;
  const currentUserId = req.user.id;

  try {
    // Check if user is blocked
    const blockCheck = await pool.query(
      'SELECT * FROM blocks WHERE blocker_id = $1 AND blocked_id = $2',
      [userId, currentUserId]
    );
    if (blockCheck.rows.length > 0) {
      return res.status(403).json({ message: 'You are blocked by this user' });
    }

    const user = await pool.query(
      'SELECT id, username, email, profile_picture, cover_image, theme_color, created_at FROM users WHERE id = $1',
      [userId]
    );
    if (user.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Get follow status
    const followCheck = await pool.query(
      'SELECT * FROM follows WHERE follower_id = $1 AND followed_id = $2',
      [currentUserId, userId]
    );
    const isFollowing = followCheck.rows.length > 0;

    // Get stats
    const postCount = await pool.query('SELECT COUNT(*) FROM posts WHERE user_id = $1', [userId]);
    const followerCount = await pool.query(
      'SELECT COUNT(*) FROM follows WHERE followed_id = $1',
      [userId]
    );
    const followingCount = await pool.query(
      'SELECT COUNT(*) FROM follows WHERE follower_id = $1',
      [userId]
    );

    // Check if blocked by current user
    const blockedByMe = await pool.query(
      'SELECT * FROM blocks WHERE blocker_id = $1 AND blocked_id = $2',
      [currentUserId, userId]
    );

    res.status(200).json({
      user: user.rows[0],
      isFollowing,
      stats: {
        posts: parseInt(postCount.rows[0].count),
        followers: parseInt(followerCount.rows[0].count),
        following: parseInt(followingCount.rows[0].count),
      },
      isBlocked: blockedByMe.rows.length > 0,
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user's followers
app.get('/api/followers/:id', authenticateToken, async (req, res) => {
  const userId = req.params.id;
  const currentUserId = req.user.id;

  try {
    // Check if blocked
    const blockCheck = await pool.query(
      'SELECT * FROM blocks WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1)',
      [userId, currentUserId]
    );
    if (blockCheck.rows.length > 0) {
      return res.status(403).json({ message: 'Cannot view followers due to block' });
    }

    const followers = await pool.query(
      `SELECT users.id, users.username, users.profile_picture
       FROM follows
       JOIN users ON follows.follower_id = users.id
       WHERE follows.followed_id = $1
       ORDER BY users.username`,
      [userId]
    );
    res.status(200).json(followers.rows);
  } catch (error) {
    console.error('Get followers error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user's following
app.get('/api/following/:id', authenticateToken, async (req, res) => {
  const userId = req.params.id;
  const currentUserId = req.user.id;

  try {
    // Check if blocked
    const blockCheck = await pool.query(
      'SELECT * FROM blocks WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1)',
      [userId, currentUserId]
    );
    if (blockCheck.rows.length > 0) {
      return res.status(403).json({ message: 'Cannot view following due to block' });
    }

    const following = await pool.query(
      `SELECT users.id, users.username, users.profile_picture
       FROM follows
       JOIN users ON follows.followed_id = users.id
       WHERE follows.follower_id = $1
       ORDER BY users.username`,
      [userId]
    );
    res.status(200).json(following.rows);
  } catch (error) {
    console.error('Get following error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user's posts
app.get('/api/users/:id/posts', authenticateToken, async (req, res) => {
  const userId = req.params.id;
  const currentUserId = req.user.id;

  try {
    // Check if blocked
    const blockCheck = await pool.query(
      'SELECT * FROM blocks WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1)',
      [userId, currentUserId]
    );
    if (blockCheck.rows.length > 0) {
      return res.status(403).json({ message: 'Cannot view posts due to block' });
    }

    const posts = await pool.query(
      'SELECT posts.*, users.username, users.profile_picture FROM posts JOIN users ON posts.user_id = users.id WHERE posts.user_id = $1 ORDER BY created_at DESC',
      [userId]
    );
    res.status(200).json(posts.rows);
  } catch (error) {
    console.error('Get user posts error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update profile
app.put('/api/profile', authenticateToken, async (req, res) => {
  const { username, email, themeColor } = req.body;
  const userId = req.user.id;
  let profilePictureUrl = null;
  let coverImageUrl = null;

  try {
    // Validate inputs
    if (!username || !email) {
      return res.status(400).json({ message: 'Username and email are required' });
    }

    // Check for unique username/email
    const userCheck = await pool.query(
      'SELECT * FROM users WHERE (email = $1 OR username = $2) AND id != $3',
      [email, username, userId]
    );
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Username or email already exists' });
    }

    // Handle profile picture
    if (req.files && req.files.profilePicture) {
      const file = req.files.profilePicture;
      if (!file.mimetype.startsWith('image/')) {
        return res.status(400).json({ message: 'Profile picture must be an image' });
      }
      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: 'mini-blog/avatars' },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        stream.end(file.data);
      });
      profilePictureUrl = result.secure_url;
    }

    // Handle cover image
    if (req.files && req.files.coverImage) {
      const file = req.files.coverImage;
      if (!file.mimetype.startsWith('image/')) {
        return res.status(400).json({ message: 'Cover image must be an image' });
      }
      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: 'mini-blog/covers' },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        stream.end(file.data);
      });
      coverImageUrl = result.secure_url;
    }

    // Update user
    const updatedUser = await pool.query(
      'UPDATE users SET username = $1, email = $2, profile_picture = COALESCE($3, profile_picture), cover_image = COALESCE($4, cover_image), theme_color = COALESCE($5, theme_color) WHERE id = $6 RETURNING id, username, email, profile_picture, cover_image, theme_color',
      [username, email, profilePictureUrl, coverImageUrl, themeColor || '#3b82f6', userId]
    );

    res.status(200).json(updatedUser.rows[0]);
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete profile
app.delete('/api/profile', authenticateToken, async (req, res) => {
  const { password } = req.body;
  const userId = req.user.id;

  try {
    if (!password) {
      return res.status(400).json({ message: 'Password is required' });
    }

    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = userResult.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Incorrect password' });
    }

    // Start a transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Delete dependent records
      // 1. Delete likes on user's posts and comments
      await client.query('DELETE FROM likes WHERE post_id IN (SELECT id FROM posts WHERE user_id = $1) OR comment_id IN (SELECT id FROM comments WHERE user_id = $1)', [userId]);
      // 2. Delete comments on user's posts
      await client.query('DELETE FROM comments WHERE post_id IN (SELECT id FROM posts WHERE user_id = $1)', [userId]);
      // 3. Delete user's posts
      await client.query('DELETE FROM posts WHERE user_id = $1', [userId]);
      // 4. Delete user's likes
      await client.query('DELETE FROM likes WHERE user_id = $1', [userId]);
      // 5. Delete user's comments
      await client.query('DELETE FROM comments WHERE user_id = $1', [userId]);
      // 6. Delete follows
      await client.query('DELETE FROM follows WHERE follower_id = $1 OR followed_id = $1', [userId]);
      // 7. Delete blocks
      await client.query('DELETE FROM blocks WHERE blocker_id = $1 OR blocked_id = $1', [userId]);
      // 8. Delete notifications
      await client.query('DELETE FROM notifications WHERE sender_id = $1 OR recipient_id = $1', [userId]);
      // 9. Delete password reset tokens
      await client.query('DELETE FROM password_reset_tokens WHERE user_id = $1', [userId]);
      // 10. Delete the user
      await client.query('DELETE FROM users WHERE id = $1', [userId]);

      await client.query('COMMIT');
      res.status(200).json({ message: 'Profile deleted successfully' });
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Delete profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create post
app.post('/api/posts', authenticateToken, async (req, res) => {
  const { title, content } = req.body;
  const userId = req.user.id;
  let media = [];

  console.log('POST /api/posts - Files:', req.files);
  console.log('POST /api/posts - Body:', { title, content });

  try {
    if (!title || !content) {
      return res.status(400).json({ message: 'Title and content are required' });
    }

    if (req.files && req.files.media) {
      const files = Array.isArray(req.files.media) ? req.files.media : [req.files.media];
      console.log('POST /api/posts - Processing files:', files);

      if (files.length > 4) {
        return res.status(400).json({ message: 'Maximum 4 media files allowed' });
      }

      for (const file of files) {
        const isImage = file.mimetype.startsWith('image/');
        const isVideo = file.mimetype.startsWith('video/');
        if (!isImage && !isVideo) {
          return res.status(400).json({ message: 'Only images and videos are allowed' });
        }

        const result = await new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            {
              folder: isImage ? 'mini-blog/images' : 'mini-blog/videos',
              resource_type: isVideo ? 'video' : 'image',
            },
            (error, result) => {
              if (error) reject(error);
              else resolve(result);
            }
          );
          stream.end(file.data);
        });

        console.log('POST /api/posts - Uploaded file:', result.secure_url);
        media.push({
          url: result.secure_url,
          type: isImage ? 'image' : 'video',
        });
      }
    }

    console.log('POST /api/posts - Final media:', media);

    const newPost = await pool.query(
      'INSERT INTO posts (user_id, title, content, media, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING *',
      [userId, title, content, JSON.stringify(media)]
    );

    const post = await pool.query(
      'SELECT posts.*, users.username, users.profile_picture FROM posts JOIN users ON posts.user_id = users.id WHERE posts.id = $1',
      [newPost.rows[0].id]
    );

    res.status(201).json(post.rows[0]);
  } catch (error) {
    console.error('Create post error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get single post by ID
app.get('/api/posts/:id', authenticateToken, async (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id;

  try {
    const parsedPostId = parseInt(postId, 10);
    if (isNaN(parsedPostId)) {
      return res.status(400).json({ message: 'Invalid post ID' });
    }

    const post = await pool.query(
      `SELECT posts.*, users.username, users.profile_picture, COUNT(likes.id) as likes
       FROM posts
       JOIN users ON posts.user_id = users.id
       LEFT JOIN likes ON posts.id = likes.post_id AND likes.comment_id IS NULL
       WHERE posts.id = $1
       AND posts.user_id NOT IN (
         SELECT blocked_id FROM blocks WHERE blocker_id = $2
       )
       AND posts.user_id NOT IN (
         SELECT blocker_id FROM blocks WHERE blocked_id = $2
       )
       GROUP BY posts.id, users.id`,
      [parsedPostId, userId]
    );

    if (post.rows.length === 0) {
      return res.status(404).json({ message: 'Post not found' });
    }

    res.status(200).json(post.rows[0]);
  } catch (error) {
    console.error('Get post error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Edit post
app.put('/api/posts/:id', authenticateToken, async (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id;
  const { title, content, existingMedia } = req.body;
  let media = [];

  try {
    if (!title || !content) {
      return res.status(400).json({ message: 'Title and content are required' });
    }

    const post = await pool.query('SELECT * FROM posts WHERE id = $1 AND user_id = $2', [postId, userId]);
    if (post.rows.length === 0) {
      return res.status(403).json({ message: 'Post not found or unauthorized' });
    }

    try {
      media = existingMedia ? JSON.parse(existingMedia) : [];
      if (!Array.isArray(media)) media = [];
    } catch (error) {
      console.error('Parse existingMedia error:', error);
      media = [];
    }

    if (req.files && req.files.media) {
      const files = Array.isArray(req.files.media) ? req.files.media : [req.files.media];
      if (media.length + files.length > 4) {
        return res.status(400).json({ message: 'Maximum 4 media files allowed' });
      }

      for (const file of files) {
        const isImage = file.mimetype.startsWith('image/');
        const isVideo = file.mimetype.startsWith('video/');
        if (!isImage && !isVideo) {
          return res.status(400).json({ message: 'Only images and videos are allowed' });
        }

        const result = await new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            {
              folder: isImage ? 'mini-blog/images' : 'mini-blog/videos',
              resource_type: isVideo ? 'video' : 'image',
            },
            (error, result) => {
              if (error) reject(error);
              else resolve(result);
            }
          );
          stream.end(file.data);
        });

        media.push({
          url: result.secure_url,
          type: isImage ? 'image' : 'video',
        });
      }
    }

    const updatedPost = await pool.query(
      'UPDATE posts SET title = $1, content = $2, media = $3 WHERE id = $4 RETURNING *',
      [title, content, JSON.stringify(media), postId]
    );

    const postWithUser = await pool.query(
      'SELECT posts.*, users.username, users.profile_picture FROM posts JOIN users ON posts.user_id = users.id WHERE posts.id = $1',
      [postId]
    );

    res.status(200).json(postWithUser.rows[0]);
  } catch (error) {
    console.error('Edit post error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all posts
app.get('/api/posts', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const posts = await pool.query(
      `SELECT posts.*, users.username, users.profile_picture, COUNT(likes.id) as likes
       FROM posts
       JOIN users ON posts.user_id = users.id
       LEFT JOIN likes ON posts.id = likes.post_id AND likes.comment_id IS NULL
       WHERE posts.user_id NOT IN (
         SELECT blocked_id FROM blocks WHERE blocker_id = $1
       )
       AND posts.user_id NOT IN (
         SELECT blocker_id FROM blocks WHERE blocked_id = $1
       )
       GROUP BY posts.id, users.id
       ORDER BY posts.created_at DESC`,
      [userId]
    );
    res.status(200).json(posts.rows);
  } catch (error) {
    console.error('Get posts error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user's posts (my-posts)
app.get('/api/posts/my-posts', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const posts = await pool.query(
      'SELECT posts.*, users.username, users.profile_picture, COUNT(likes.id) as likes FROM posts JOIN users ON posts.user_id = users.id LEFT JOIN likes ON posts.id = likes.post_id AND likes.comment_id IS NULL WHERE posts.user_id = $1 GROUP BY posts.id, users.id ORDER BY posts.created_at DESC',
      [userId]
    );
    res.status(200).json(posts.rows);
  } catch (error) {
    console.error('Get my posts error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete post
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id;

  try {
    const parsedPostId = parseInt(postId, 10);
    if (isNaN(parsedPostId)) {
      return res.status(400).json({ message: 'Invalid post ID' });
    }

    const post = await pool.query('SELECT * FROM posts WHERE id = $1', [parsedPostId]);
    if (post.rows.length === 0) {
      return res.status(404).json({ message: 'Post not found' });
    }
    if (post.rows[0].user_id !== userId) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    // Delete the post; cascading deletes will handle likes and shared posts
    await pool.query('DELETE FROM posts WHERE id = $1', [parsedPostId]);
    res.status(200).json({ message: 'Post deleted' });
  } catch (error) {
    console.error('Delete post error:', error);
    res.status(500).json({ message: 'Failed to delete post' });
  }
});

// Follow user
app.post('/api/follow', authenticateToken, async (req, res) => {
  const { followedId } = req.body;
  const followerId = req.user.id;

  try {
    if (followerId === followedId) {
      return res.status(400).json({ message: 'Cannot follow yourself' });
    }

    const userCheck = await pool.query('SELECT * FROM users WHERE id = $1', [followedId]);
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if blocked
    const blockCheck = await pool.query(
      'SELECT * FROM blocks WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1)',
      [followerId, followedId]
    );
    if (blockCheck.rows.length > 0) {
      return res.status(403).json({ message: 'Cannot follow due to block' });
    }

    const followCheck = await pool.query(
      'SELECT * FROM follows WHERE follower_id = $1 AND followed_id = $2',
      [followerId, followedId]
    );
    if (followCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Already following' });
    }

    await pool.query(
      'INSERT INTO follows (follower_id, followed_id) VALUES ($1, $2)',
      [followerId, followedId]
    );

    res.status(200).json({ message: 'Followed successfully' });
  } catch (error) {
    console.error('Follow error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Unfollow user
app.delete('/api/follow/:followedId', authenticateToken, async (req, res) => {
  const followedId = req.params.followedId;
  const followerId = req.user.id;

  try {
    const followCheck = await pool.query(
      'SELECT * FROM follows WHERE follower_id = $1 AND followed_id = $2',
      [followerId, followedId]
    );
    if (followCheck.rows.length === 0) {
      return res.status(400).json({ message: 'Not following this user' });
    }

    await pool.query(
      'DELETE FROM follows WHERE follower_id = $1 AND followed_id = $2',
      [followerId, followedId]
    );

    res.status(200).json({ message: 'Unfollowed successfully' });
  } catch (error) {
    console.error('Unfollow error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Block user
app.post('/api/block', authenticateToken, async (req, res) => {
  const { blockedId } = req.body;
  const blockerId = req.user.id;

  try {
    if (blockerId === blockedId) {
      return res.status(400).json({ message: 'Cannot block yourself' });
    }

    const userCheck = await pool.query('SELECT * FROM users WHERE id = $1', [blockedId]);
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const blockCheck = await pool.query(
      'SELECT * FROM blocks WHERE blocker_id = $1 AND blocked_id = $2',
      [blockerId, blockedId]
    );
    if (blockCheck.rows.length > 0) {
      return res.status(400).json({ message: 'User already blocked' });
    }

    // Remove any follows
    await pool.query(
      'DELETE FROM follows WHERE (follower_id = $1 AND followed_id = $2) OR (follower_id = $2 AND followed_id = $1)',
      [blockerId, blockedId]
    );

    await pool.query(
      'INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1, $2)',
      [blockerId, blockedId]
    );

    res.status(200).json({ message: 'User blocked' });
  } catch (error) {
    console.error('Block error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Unblock user
app.delete('/api/block/:blockedId', authenticateToken, async (req, res) => {
  const blockedId = req.params.blockedId;
  const blockerId = req.user.id;

  try {
    const blockCheck = await pool.query(
      'SELECT * FROM blocks WHERE blocker_id = $1 AND blocked_id = $2',
      [blockerId, blockedId]
    );
    if (blockCheck.rows.length === 0) {
      return res.status(400).json({ message: 'User not blocked' });
    }

    await pool.query(
      'DELETE FROM blocks WHERE blocker_id = $1 AND blocked_id = $2',
      [blockerId, blockedId]
    );

    res.status(200).json({ message: 'User unblocked' });
  } catch (error) {
    console.error('Unblock error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get blocked users
app.get('/api/blocked', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const blocked = await pool.query(
      `SELECT users.id, users.username, users.profile_picture
       FROM blocks
       JOIN users ON blocks.blocked_id = users.id
       WHERE blocks.blocker_id = $1
       ORDER BY blocks.created_at DESC`,
      [userId]
    );

    res.status(200).json(blocked.rows);
  } catch (error) {
    console.error('Get blocked users error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Search users
app.get('/api/search/users', authenticateToken, async (req, res) => {
  const { query } = req.query;
  const userId = req.user.id;

  try {
    if (!query || query.trim().length < 1) {
      return res.status(400).json({ message: 'Query is required' });
    }

    const users = await pool.query(
      `SELECT id, username, profile_picture
       FROM users
       WHERE username ILIKE $1
       AND id != $2
       AND id NOT IN (
         SELECT blocked_id FROM blocks WHERE blocker_id = $2
       )
       AND id NOT IN (
         SELECT blocker_id FROM blocks WHERE blocked_id = $2
       )
       ORDER BY username
       LIMIT 20`,
      [`%${query.trim()}%`, userId]
    );

    const usersWithFollowStatus = await Promise.all(
      users.rows.map(async (user) => {
        const followCheck = await pool.query(
          'SELECT * FROM follows WHERE follower_id = $1 AND followed_id = $2',
          [userId, user.id]
        );
        return {
          ...user,
          isFollowing: followCheck.rows.length > 0,
        };
      })
    );

    res.status(200).json(usersWithFollowStatus);
  } catch (error) {
    console.error('Search users error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Search posts
app.get('/api/search/posts', authenticateToken, async (req, res) => {
  const { query } = req.query;
  const userId = req.user.id;

  try {
    if (!query || query.trim().length < 1) {
      return res.status(400).json({ message: 'Query is required' });
    }

    const posts = await pool.query(
      `SELECT posts.*, users.username, users.profile_picture, COUNT(likes.id) as likes
       FROM posts
       JOIN users ON posts.user_id = users.id
       LEFT JOIN likes ON posts.id = likes.post_id AND likes.comment_id IS NULL
       WHERE (posts.title ILIKE $1 OR posts.content ILIKE $1)
       AND posts.user_id NOT IN (
         SELECT blocked_id FROM blocks WHERE blocker_id = $2
       )
       AND posts.user_id NOT IN (
         SELECT blocker_id FROM blocks WHERE blocked_id = $2
       )
       GROUP BY posts.id, users.id
       ORDER BY posts.created_at DESC
       LIMIT 20`,
      [`%${query.trim()}%`, userId]
    );

    res.status(200).json(posts.rows);
  } catch (error) {
    console.error('Search posts error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get suggested users
app.get('/api/suggestions', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const suggestions = await pool.query(
      `SELECT id, username, profile_picture
       FROM users
       WHERE id != $1
       AND id NOT IN (
         SELECT followed_id FROM follows WHERE follower_id = $1
       )
       AND id NOT IN (
         SELECT blocked_id FROM blocks WHERE blocker_id = $1
       )
       AND id NOT IN (
         SELECT blocker_id FROM blocks WHERE blocked_id = $1
       )
       ORDER BY RANDOM()
       LIMIT 5`,
      [userId]
    );

    const suggestionsWithFollowStatus = suggestions.rows.map((user) => ({
      ...user,
      isFollowing: false,
    }));

    res.status(200).json(suggestionsWithFollowStatus);
  } catch (error) {
    console.error('Get suggestions error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create comment
app.post('/api/comments', authenticateToken, async (req, res) => {
  const { postId, content, parentCommentId } = req.body;
  const userId = req.user.id;

  try {
    if (!postId || !content?.trim()) {
      return res.status(400).json({ message: 'Post ID and content are required' });
    }

    const parsedPostId = parseInt(postId, 10);
    const parsedParentId = parentCommentId ? parseInt(parentCommentId, 10) : null;
    if (isNaN(parsedPostId)) {
      return res.status(400).json({ message: 'Invalid post ID' });
    }
    if (parentCommentId && isNaN(parsedParentId)) {
      return res.status(400).json({ message: 'Invalid parent comment ID' });
    }

    const post = await pool.query('SELECT user_id FROM posts WHERE id = $1', [parsedPostId]);
    if (post.rows.length === 0) {
      return res.status(404).json({ message: 'Post not found' });
    }

    // Check if blocked
    const blockCheck = await pool.query(
      'SELECT * FROM blocks WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1)',
      [userId, post.rows[0].user_id]
    );
    if (blockCheck.rows.length > 0) {
      return res.status(403).json({ message: 'Cannot comment due to block' });
    }

    if (parsedParentId) {
      const parent = await pool.query('SELECT id FROM comments WHERE id = $1 AND post_id = $2', [parsedParentId, parsedPostId]);
      if (parent.rows.length === 0) {
        return res.status(404).json({ message: 'Parent comment not found' });
      }
    }

    const comment = await pool.query(
      `INSERT INTO comments (post_id, user_id, content, parent_comment_id, created_at)
       VALUES ($1, $2, $3, $4, NOW())
       RETURNING id, post_id, user_id, content, parent_comment_id, created_at, updated_at`,
      [parsedPostId, userId, content, parsedParentId]
    );

    const user = await pool.query('SELECT username, profile_picture FROM users WHERE id = $1', [userId]);
    res.status(201).json({
      ...comment.rows[0],
      username: user.rows[0].username,
      profile_picture: user.rows[0].profile_picture,
      likes: 0,
      isLiked: false,
      replies: [],
    });
  } catch (error) {
    console.error('Create comment error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});


// Edit comment
app.put('/api/comments/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { content } = req.body;
  const userId = req.user.id;

  try {
    if (!content || !content.trim()) {
      return res.status(400).json({ message: 'Comment content is required' });
    }

    // Check if comment exists
    const comment = await pool.query('SELECT * FROM comments WHERE id = $1', [id]);
    if (comment.rows.length === 0) {
      return res.status(404).json({ message: 'Comment not found' });
    }
    if (comment.rows[0].user_id !== userId) {
      return res.status(403).json({ message: 'Unauthorized to edit this comment' });
    }

    // Update comment
    const updatedComment = await pool.query(
      'UPDATE comments SET content = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING id, user_id, post_id, content, parent_comment_id, created_at, updated_at',
      [content.trim(), id]
    );

    if (updatedComment.rows.length === 0) {
      return res.status(500).json({ message: 'Failed to update comment' });
    }

    const user = await pool.query('SELECT username, profile_picture FROM users WHERE id = $1', [userId]);
    const likesResult = await pool.query('SELECT COUNT(*) FROM likes WHERE comment_id = $1', [id]);
    const isLikedResult = await pool.query(
      'SELECT EXISTS(SELECT 1 FROM likes WHERE user_id = $1 AND comment_id = $2)',
      [userId, id]
    );

    res.status(200).json({
      ...updatedComment.rows[0],
      username: user.rows[0].username,
      profile_picture: user.rows[0].profile_picture,
      likes: parseInt(likesResult.rows[0].count),
      isLiked: isLikedResult.rows[0].exists,
      replies: comment.rows[0].replies || [],
    });
  } catch (error) {
    console.error('Update comment error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete comment
app.delete('/api/comments/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  try {
    // Check if comment exists
    const comment = await pool.query('SELECT * FROM comments WHERE id = $1', [id]);
    if (comment.rows.length === 0) {
      return res.status(404).json({ message: 'Comment not found' });
    }
    if (comment.rows[0].user_id !== userId) {
      return res.status(403).json({ message: 'Unauthorized to delete this comment' });
    }

    // Delete the comment (cascading deletes will handle replies and likes)
    await pool.query('DELETE FROM comments WHERE id = $1', [id]);

    res.status(200).json({ message: 'Comment and its replies deleted' });
  } catch (error) {
    console.error('Delete comment error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get comments for a post

app.get('/api/comments/:postId', authenticateToken, async (req, res) => {
  const postId = req.params.postId;
  const userId = req.user.id;

  try {
    const parsedPostId = parseInt(postId, 10);
    if (isNaN(parsedPostId)) {
      return res.status(400).json({ message: 'Invalid post ID' });
    }

    const post = await pool.query('SELECT user_id FROM posts WHERE id = $1', [parsedPostId]);
    if (post.rows.length === 0) {
      return res.status(404).json({ message: 'Post not found' });
    }

    // Check if blocked
    const blockCheck = await pool.query(
      'SELECT * FROM blocks WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1)',
      [userId, post.rows[0].user_id]
    );
    if (blockCheck.rows.length > 0) {
      return res.status(403).json({ message: 'Cannot view comments due to block' });
    }

    const comments = await pool.query(
      `SELECT c.*, u.username, u.profile_picture, 
              COUNT(l.id) as likes,
              EXISTS(SELECT 1 FROM likes l2 WHERE l2.comment_id = c.id AND l2.user_id = $2) as is_liked
       FROM comments c
       LEFT JOIN users u ON c.user_id = u.id
       LEFT JOIN likes l ON c.id = l.comment_id
       WHERE c.post_id = $1
       AND (c.user_id NOT IN (
         SELECT blocked_id FROM blocks WHERE blocker_id = $2
       ) OR c.user_id IS NULL)
       AND (c.user_id NOT IN (
         SELECT blocker_id FROM blocks WHERE blocked_id = $2
       ) OR c.user_id IS NULL)
       GROUP BY c.id, u.id
       ORDER BY c.pinned DESC, c.created_at ASC`,
      [parsedPostId, userId]
    );

    // Build comment tree
    const commentMap = {};
    const result = [];
    comments.rows.forEach((c) => {
      c.replies = [];
      c.likes = parseInt(c.likes);
      c.isLiked = c.is_liked;
      delete c.is_liked;
      commentMap[c.id] = c;
      if (c.parent_comment_id && commentMap[c.parent_comment_id]) {
        commentMap[c.parent_comment_id].replies.push(c);
      } else {
        result.push(c);
      }
    });

    res.status(200).json(result);
  } catch (error) {
    console.error('Get comments error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

// Check if user liked a comment
app.get('/api/comments/:id/like', authenticateToken, async (req, res) => {
  const commentId = req.params.id;
  const userId = req.user.id;

  try {
    const parsedCommentId = parseInt(commentId, 10);
    if (isNaN(parsedCommentId)) {
      return res.status(400).json({ message: 'Invalid comment ID' });
    }

    const result = await pool.query(
      'SELECT EXISTS(SELECT 1 FROM likes WHERE user_id = $1 AND comment_id = $2)',
      [userId, parsedCommentId]
    );
    const isLiked = result.rows[0].exists;
    res.json({ isLiked });
  } catch (error) {
    console.error('Check comment like error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Like a comment
app.post('/api/comments/:id/like', authenticateToken, async (req, res) => {
  const commentId = req.params.id;
  const userId = req.user.id;

  try {
    const parsedCommentId = parseInt(commentId, 10);
    if (isNaN(parsedCommentId)) {
      return res.status(400).json({ message: 'Invalid comment ID' });
    }

    const comment = await pool.query('SELECT user_id, post_id FROM comments WHERE id = $1', [parsedCommentId]);
    if (comment.rows.length === 0) {
      return res.status(404).json({ message: 'Comment not found' });
    }

    // Check if blocked
    const blockCheck = await pool.query(
      'SELECT * FROM blocks WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1)',
      [userId, comment.rows[0].user_id]
    );
    if (blockCheck.rows.length > 0) {
      return res.status(403).json({ message: 'Cannot like comment due to block' });
    }

    await pool.query(
      'INSERT INTO likes (user_id, comment_id) VALUES ($1, $2)',
      [userId, parsedCommentId]
    );

    const likesResult = await pool.query(
      'SELECT COUNT(*) FROM likes WHERE comment_id = $1',
      [parsedCommentId]
    );
    const likes = parseInt(likesResult.rows[0].count, 10);

    res.json({ message: 'Comment liked', likes });
  } catch (error) {
    if (error.code === '23505') { // Unique violation
      return res.status(400).json({ message: 'Comment already liked' });
    }
    console.error('Like comment error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Unlike a comment
app.delete('/api/comments/:id/like', authenticateToken, async (req, res) => {
  const commentId = req.params.id;
  const userId = req.user.id;

  try {
    const parsedCommentId = parseInt(commentId, 10);
    if (isNaN(parsedCommentId)) {
      return res.status(400).json({ message: 'Invalid comment ID' });
    }

    const deleteResult = await pool.query(
      'DELETE FROM likes WHERE user_id = $1 AND comment_id = $2 RETURNING *',
      [userId, parsedCommentId]
    );
    if (deleteResult.rowCount === 0) {
      return res.status(404).json({ message: 'Like not found' });
    }

    const likesResult = await pool.query(
      'SELECT COUNT(*) FROM likes WHERE comment_id = $1',
      [parsedCommentId]
    );
    const likes = parseInt(likesResult.rows[0].count, 10);

    res.json({ message: 'Comment unliked', likes });
  } catch (error) {
    console.error('Unlike comment error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Pin a comment
app.put('/api/comments/:id/pin', authenticateToken, async (req, res) => {
  const commentId = req.params.id;
  const userId = req.user.id;

  try {
    const parsedCommentId = parseInt(commentId, 10);
    if (isNaN(parsedCommentId)) {
      return res.status(400).json({ message: 'Invalid comment ID' });
    }

    // Verify comment exists and get post ID
    const comment = await pool.query('SELECT post_id, user_id FROM comments WHERE id = $1', [parsedCommentId]);
    if (comment.rows.length === 0) {
      return res.status(404).json({ message: 'Comment not found' });
    }

    const postId = comment.rows[0].post_id;

    // Verify post exists and user is the post author
    const post = await pool.query('SELECT user_id FROM posts WHERE id = $1', [postId]);
    if (post.rows.length === 0) {
      return res.status(404).json({ message: 'Post not found' });
    }
    if (post.rows[0].user_id !== userId) {
      return res.status(403).json({ message: 'Only the post author can pin comments' });
    }

    // Check if blocked
    const blockCheck = await pool.query(
      'SELECT * FROM blocks WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1)',
      [userId, comment.rows[0].user_id]
    );
    if (blockCheck.rows.length > 0) {
      return res.status(403).json({ message: 'Cannot pin comment due to block' });
    }

    // Unpin any existing pinned comment for this post
    await pool.query(
      'UPDATE comments SET pinned = FALSE WHERE post_id = $1 AND pinned = TRUE',
      [postId]
    );

    // Pin the selected comment
    await pool.query('UPDATE comments SET pinned = TRUE WHERE id = $1', [parsedCommentId]);

    res.status(200).json({ message: 'Comment pinned' });
  } catch (error) {
    console.error('Pin comment error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Unpin a comment
app.put('/api/comments/:id/unpin', authenticateToken, async (req, res) => {
  const commentId = req.params.id;
  const userId = req.user.id;

  try {
    const parsedCommentId = parseInt(commentId, 10);
    if (isNaN(parsedCommentId)) {
      return res.status(400).json({ message: 'Invalid comment ID' });
    }

    // Verify comment exists and get post ID
    const comment = await pool.query('SELECT post_id, user_id FROM comments WHERE id = $1', [parsedCommentId]);
    if (comment.rows.length === 0) {
      return res.status(404).json({ message: 'Comment not found' });
    }

    const postId = comment.rows[0].post_id;

    // Verify post exists and user is the post author
    const post = await pool.query('SELECT user_id FROM posts WHERE id = $1', [postId]);
    if (post.rows.length === 0) {
      return res.status(404).json({ message: 'Post not found' });
    }
    if (post.rows[0].user_id !== userId) {
      return res.status(403).json({ message: 'Only the post author can unpin comments' });
    }

    // Check if blocked
    const blockCheck = await pool.query(
      'SELECT * FROM blocks WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1)',
      [userId, comment.rows[0].user_id]
    );
    if (blockCheck.rows.length > 0) {
      return res.status(403).json({ message: 'Cannot unpin comment due to block' });
    }

    // Unpin the comment
    await pool.query('UPDATE comments SET pinned = FALSE WHERE id = $1', [parsedCommentId]);

    res.status(200).json({ message: 'Comment unpinned' });
  } catch (error) {
    console.error('Unpin comment error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Check if user liked a post
app.get('/api/posts/:id/like', authenticateToken, async (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id;

  try {
    const parsedPostId = parseInt(postId, 10);
    if (isNaN(parsedPostId)) {
      return res.status(400).json({ message: 'Invalid post ID' });
    }

    const result = await pool.query(
      'SELECT EXISTS(SELECT 1 FROM likes WHERE user_id = $1 AND post_id = $2)',
      [userId, parsedPostId]
    );
    const isLiked = result.rows[0].exists;
    res.json({ isLiked });
  } catch (error) {
    console.error('Check like error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Like a post
app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id;

  try {
    const parsedPostId = parseInt(postId, 10);
    if (isNaN(parsedPostId)) {
      return res.status(400).json({ message: 'Invalid post ID' });
    }

    const post = await pool.query('SELECT user_id FROM posts WHERE id = $1', [parsedPostId]);
    if (post.rows.length === 0) {
      return res.status(404).json({ message: 'Post not found' });
    }

    // Check if blocked
    const blockCheck = await pool.query(
      'SELECT * FROM blocks WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1)',
      [userId, post.rows[0].user_id]
    );
    if (blockCheck.rows.length > 0) {
      return res.status(403).json({ message: 'Cannot like post due to block' });
    }

    await pool.query(
      'INSERT INTO likes (user_id, post_id) VALUES ($1, $2)',
      [userId, parsedPostId]
    );

    const likesResult = await pool.query(
      'SELECT COUNT(*) FROM likes WHERE post_id = $1',
      [parsedPostId]
    );
    const likes = parseInt(likesResult.rows[0].count, 10);

    res.json({ message: 'Post liked', likes });
  } catch (error) {
    if (error.code === '23505') { // Unique violation
      return res.status(400).json({ message: 'Post already liked' });
    }
    console.error('Like post error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Unlike a post
app.delete('/api/posts/:id/like', authenticateToken, async (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id;

  try {
    const parsedPostId = parseInt(postId, 10);
    if (isNaN(parsedPostId)) {
      return res.status(400).json({ message: 'Invalid post ID' });
    }

    const deleteResult = await pool.query(
      'DELETE FROM likes WHERE user_id = $1 AND post_id = $2 RETURNING *',
      [userId, parsedPostId]
    );
    if (deleteResult.rowCount === 0) {
      return res.status(404).json({ message: 'Like not found' });
    }

    const likesResult = await pool.query(
      'SELECT COUNT(*) FROM likes WHERE post_id = $1',
      [parsedPostId]
    );
    const likes = parseInt(likesResult.rows[0].count, 10);

    res.json({ message: 'Post unliked', likes });
  } catch (error) {
    console.error('Unlike post error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});
// Share a post
app.post('/api/posts/share', authenticateToken, async (req, res) => {
  const { postId } = req.body;
  const userId = req.user.id;

  try {
    const parsedPostId = parseInt(postId, 10);
    if (isNaN(parsedPostId)) {
      return res.status(400).json({ message: 'Invalid post ID' });
    }

    const originalPostResult = await pool.query(
      'SELECT posts.*, users.username AS original_username, users.profile_picture AS original_profile_picture FROM posts JOIN users ON posts.user_id = users.id WHERE posts.id = $1',
      [parsedPostId]
    );
    if (originalPostResult.rowCount === 0) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const originalPost = originalPostResult.rows[0];

    // Check if blocked
    const blockCheck = await pool.query(
      'SELECT * FROM blocks WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1)',
      [userId, originalPost.user_id]
    );
    if (blockCheck.rows.length > 0) {
      return res.status(403).json({ message: 'Cannot share post due to block' });
    }

    // Handle original media (JSONB returns as object)
    let originalMedia = [];
    if (originalPost.media) {
      if (Array.isArray(originalPost.media)) {
        originalMedia = originalPost.media;
      } else {
        console.warn(`Media for post ${parsedPostId} is not an array:`, originalPost.media);
        originalMedia = [];
      }
    }

    // Create a new post as a share, attributing to sharer
    const newPost = await pool.query(
      'INSERT INTO posts (user_id, title, content, media, shared_from_post_id, shared_by_user_id, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING *',
      [
        userId, // Sharer’s user_id
        originalPost.title || '', // Ensure title is not null
        originalPost.content || '', // Ensure content is not null
        JSON.stringify(originalMedia), // Stringify for JSONB
        parsedPostId,
        userId,
      ]
    );

    const sharerResult = await pool.query(
      'SELECT id, username, profile_picture FROM users WHERE id = $1',
      [userId]
    );

    const postWithUser = await pool.query(
      'SELECT posts.*, users.username, users.profile_picture, COUNT(likes.id) as likes FROM posts JOIN users ON posts.user_id = users.id LEFT JOIN likes ON posts.id = likes.post_id AND likes.comment_id IS NULL WHERE posts.id = $1 GROUP BY posts.id, users.id',
      [newPost.rows[0].id]
    );

    const post = postWithUser.rows[0];
    let media = [];
    if (post.media) {
      if (Array.isArray(post.media)) {
        media = post.media;
      } else {
        console.warn(`Media for new post ${post.id} is not an array:`, post.media);
        media = [];
      }
    }

    res.status(201).json({
      ...post,
      media,
      isLiked: false,
      original_username: originalPost.original_username, // For "Shared From"
    });
  } catch (error) {
    console.error('Share post error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get feed
app.get('/api/posts/feed', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const postsResult = await pool.query(
      `SELECT 
         posts.*, 
         users.username, 
         users.profile_picture, 
         COUNT(likes.id) as likes,
         EXISTS (
           SELECT 1 FROM likes 
           WHERE likes.post_id = posts.id 
           AND likes.user_id = $1
           AND likes.comment_id IS NULL
         ) as is_liked,
         (SELECT username FROM users WHERE users.id = original_posts.user_id) as original_username
       FROM posts 
       JOIN users ON posts.user_id = users.id 
       LEFT JOIN posts AS original_posts ON posts.shared_from_post_id = original_posts.id
       LEFT JOIN likes ON posts.id = likes.post_id AND likes.comment_id IS NULL
       WHERE posts.user_id NOT IN (
         SELECT blocked_id FROM blocks WHERE blocker_id = $1
         UNION
         SELECT blocker_id FROM blocks WHERE blocked_id = $1
       )
       GROUP BY posts.id, users.id, original_posts.user_id
       ORDER BY posts.created_at DESC
       LIMIT 20`,
      [userId]
    );

    res.json(postsResult.rows.map((post) => {
      let media = [];
      if (post.media) {
        if (Array.isArray(post.media)) {
          media = post.media;
        } else {
          console.warn(`Media for post ${post.id} is not an array:`, post.media);
          media = [];
        }
      }
      return {
        ...post,
        media,
        isLiked: post.is_liked,
      };
    }));
  } catch (error) {
    console.error('Feed error:', error);
    res.status(500).json({ message: 'Failed to fetch feed' });
  }
});

// Send notification email
app.post('/api/notifications', authenticateToken, async (req, res) => {
  const { type, recipientId, postId, senderId, commentId } = req.body;

  try {
    // Validate inputs
    if (!type || !recipientId || !senderId) {
      return res.status(400).json({ message: 'Type, recipientId, and senderId are required' });
    }
    if (!['like', 'comment', 'reply', 'share', 'follow', 'comment_like'].includes(type)) {
      return res.status(400).json({ message: 'Invalid notification type' });
    }
    if (['like', 'comment', 'reply', 'share', 'comment_like'].includes(type) && !postId) {
      return res.status(400).json({ message: 'postId is required for this notification type' });
    }
    if (type === 'comment_like' && !commentId) {
      return res.status(400).json({ message: 'commentId is required for comment_like notification' });
    }

    // Prevent self-notifications
    if (recipientId === senderId) {
      return res.status(400).json({ message: 'Cannot notify yourself' });
    }

    // Fetch sender and recipient
    const recipientResult = await pool.query(
      'SELECT id, username, email FROM users WHERE id = $1',
      [recipientId]
    );
    if (recipientResult.rows.length === 0) {
      return res.status(404).json({ message: 'Recipient not found' });
    }
    const recipient = recipientResult.rows[0];

    const senderResult = await pool.query(
      'SELECT username FROM users WHERE id = $1',
      [senderId]
    );
    if (senderResult.rows.length === 0) {
      return res.status(404).json({ message: 'Sender not found' });
    }
    const sender = senderResult.rows[0];

    // Check if blocked
    const blockCheck = await pool.query(
      'SELECT * FROM blocks WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1)',
      [recipientId, senderId]
    );
    if (blockCheck.rows.length > 0) {
      return res.status(403).json({ message: 'Cannot send notification due to block' });
    }

    // Check if post is muted (for post-related notifications)
    if (['like', 'comment', 'reply', 'share', 'comment_like'].includes(type)) {
      const muteCheck = await pool.query(
        'SELECT EXISTS (SELECT 1 FROM muted_posts WHERE user_id = $1 AND post_id = $2) AS is_muted',
        [recipientId, postId]
      );
      if (muteCheck.rows[0].is_muted) {
        return res.status(200).json({ message: 'Notification skipped (post muted)' });
      }
    }

    // For post-related notifications, verify post and get title
    let postTitle = '';
    let postLink = '';
    if (['like', 'comment', 'reply', 'share', 'comment_like'].includes(type)) {
      const postResult = await pool.query(
        'SELECT title FROM posts WHERE id = $1',
        [postId]
      );
      if (postResult.rows.length === 0) {
        return res.status(404).json({ message: 'Post not found' });
      }
      postTitle = postResult.rows[0].title;
      postLink = `${process.env.FRONTEND_URL}/post/${postId}`;
    }

    // For comment_like, verify comment
    if (type === 'comment_like') {
      const commentResult = await pool.query(
        'SELECT id FROM comments WHERE id = $1',
        [commentId]
      );
      if (commentResult.rows.length === 0) {
        return res.status(404).json({ message: 'Comment not found' });
      }
    }

    // Rate limiting: Check notification count in last hour
    const notificationCount = await pool.query(
      `SELECT COUNT(*) FROM notifications
       WHERE recipient_id = $1
       AND created_at > NOW() - INTERVAL '1 hour'`,
      [recipientId]
    );
    if (parseInt(notificationCount.rows[0].count) >= 100) {
      return res.status(429).json({ message: 'Notification limit reached' });
    }

    // Log notification to database
    await pool.query(
      'INSERT INTO notifications (recipient_id, sender_id, type, post_id, comment_id, created_at) VALUES ($1, $2, $3, $4, $5, NOW())',
      [recipientId, senderId, type, postId || null, commentId || null]
    );

    // Configure Nodemailer
    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    // Construct email
    let subject, htmlContent, textContent;
    const profileLink = `${process.env.FRONTEND_URL}/profile/${senderId}`;
    switch (type) {
      case 'like':
        subject = `${sender.username} liked your post`;
        textContent = `Hello ${recipient.username},\n\n${sender.username} liked your post "${postTitle}".\nView it here: ${postLink}\n\nBest,\nMini Blog Team`;
        htmlContent = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #1e40af;">Mini Blog Notification</h2>
            <p>Hello ${recipient.username},</p>
            <p><a href="${profileLink}" style="color: #1e40af; text-decoration: none;">${sender.username}</a> liked your post "<a href="${postLink}" style="color: #1e40af; text-decoration: none;">${postTitle}</a>".</p>
            <a href="${postLink}" style="display: inline-block; padding: 10px 20px; background-color: #1e40af; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">
              View Post
            </a>
            <p>Best regards,<br>The Mini Blog Team</p>
            <hr style="border-top: 1px solid #e5e7eb; margin-top: 20px;">
            <p style="font-size: 12px; color: #6b7280;">Mini Blog © 2025</p>
          </div>
        `;
        break;
      case 'comment':
        subject = `${sender.username} commented on your post`;
        textContent = `Hello ${recipient.username},\n\n${sender.username} commented on your post "${postTitle}".\nView it here: ${postLink}\n\nBest,\nMini Blog Team`;
        htmlContent = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #1e40af;">Mini Blog Notification</h2>
            <p>Hello ${recipient.username},</p>
            <p><a href="${profileLink}" style="color: #1e40af; text-decoration: none;">${sender.username}</a> commented on your post "<a href="${postLink}" style="color: #1e40af; text-decoration: none;">${postTitle}</a>".</p>
            <a href="${postLink}" style="display: inline-block; padding: 10px 20px; background-color: #1e40af; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">
              View Post
            </a>
            <p>Best regards,<br>The Mini Blog Team</p>
            <hr style="border-top: 1px solid #e5e7eb; margin-top: 20px;">
            <p style="font-size: 12px; color: #6b7280;">Mini Blog © 2025</p>
          </div>
        `;
        break;
      case 'reply':
        subject = `${sender.username} replied to your comment`;
        textContent = `Hello ${recipient.username},\n\n${sender.username} replied to your comment on the post "${postTitle}".\nView it here: ${postLink}\n\nBest,\nMini Blog Team`;
        htmlContent = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #1e40af;">Mini Blog Notification</h2>
            <p>Hello ${recipient.username},</p>
            <p><a href="${profileLink}" style="color: #1e40af; text-decoration: none;">${sender.username}</a> replied to your comment on "<a href="${postLink}" style="color: #1e40af; text-decoration: none;">${postTitle}</a>".</p>
            <a href="${postLink}" style="display: inline-block; padding: 10px 20px; background-color: #1e40af; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">
              View Post
            </a>
            <p>Best regards,<br>The Mini Blog Team</p>
            <hr style="border-top: 1px solid #e5e7eb; margin-top: 20px;">
            <p style="font-size: 12px; color: #6b7280;">Mini Blog © 2025</p>
          </div>
        `;
        break;
      case 'share':
        subject = `${sender.username} shared your post`;
        textContent = `Hello ${recipient.username},\n\n${sender.username} shared your post "${postTitle}".\nView it here: ${postLink}\n\nBest,\nMini Blog Team`;
        htmlContent = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #1e40af;">Mini Blog Notification</h2>
            <p>Hello ${recipient.username},</p>
            <p><a href="${profileLink}" style="color: #1e40af; text-decoration: none;">${sender.username}</a> shared your post "<a href="${postLink}" style="color: #1e40af; text-decoration: none;">${postTitle}</a>".</p>
            <a href="${postLink}" style="display: inline-block; padding: 10px 20px; background-color: #1e40af; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">
              View Post
            </a>
            <p>Best regards,<br>The Mini Blog Team</p>
            <hr style="border-top: 1px solid #e5e7eb; margin-top: 20px;">
            <p style="font-size: 12px; color: #6b7280;">Mini Blog © 2025</p>
          </div>
        `;
        break;
      case 'follow':
        subject = `${sender.username} followed you`;
        textContent = `Hello ${recipient.username},\n\n${sender.username} followed you.\nView their profile: ${profileLink}\n\nBest,\nMini Blog Team`;
        htmlContent = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #1e40af;">Mini Blog Notification</h2>
            <p>Hello ${recipient.username},</p>
            <p><a href="${profileLink}" style="color: #1e40af; text-decoration: none;">${sender.username}</a> followed you.</p>
            <a href="${profileLink}" style="display: inline-block; padding: 10px 20px; background-color: #1e40af; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">
              View Profile
            </a>
            <p>Best regards,<br>The Mini Blog Team</p>
            <hr style="border-top: 1px solid #e5e7eb; margin-top: 20px;">
            <p style="font-size: 12px; color: #6b7280;">Mini Blog © 2025</p>
          </div>
        `;
        break;
      case 'comment_like':
        subject = `${sender.username} liked your comment`;
        textContent = `Hello ${recipient.username},\n\n${sender.username} liked your comment on the post "${postTitle}".\nView it here: ${postLink}\n\nBest,\nMini Blog Team`;
        htmlContent = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #1e40af;">Mini Blog Notification</h2>
            <p>Hello ${recipient.username},</p>
            <p><a href="${profileLink}" style="color: #1e40af; text-decoration: none;">${sender.username}</a> liked your comment on "<a href="${postLink}" style="color: #1e40af; text-decoration: none;">${postTitle}</a>".</p>
            <a href="${postLink}" style="display: inline-block; padding: 10px 20px; background-color: #1e40af; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">
              View Post
            </a>
            <p>Best regards,<br>The Mini Blog Team</p>
            <hr style="border-top: 1px solid #e5e7eb; margin-top: 20px;">
            <p style="font-size: 12px; color: #6b7280;">Mini Blog © 2025</p>
          </div>
        `;
        break;
      default:
        return res.status(400).json({ message: 'Invalid notification type' });
    }

    // Send email
    await transporter.sendMail({
      from: `"Mini Blog" <${process.env.EMAIL_USER}>`,
      to: recipient.email,
      subject,
      text: textContent,
      html: htmlContent,
    });

    res.status(200).json({ message: 'Notification sent' });
  } catch (error) {
    console.error('Notification error:', error);
    res.status(500).json({ message: 'Failed to send notification' });
  }
});

// Mute a post
app.post('/api/posts/:id/mute', authenticateToken, async (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id;

  try {
    const parsedPostId = parseInt(postId, 10);
    if (isNaN(parsedPostId)) {
      return res.status(400).json({ message: 'Invalid post ID' });
    }

    const post = await pool.query('SELECT id FROM posts WHERE id = $1', [parsedPostId]);
    if (post.rows.length === 0) {
      return res.status(404).json({ message: 'Post not found' });
    }

    await pool.query(
      'INSERT INTO muted_posts (user_id, post_id) VALUES ($1, $2) ON CONFLICT (user_id, post_id) DO NOTHING',
      [userId, parsedPostId]
    );

    res.status(200).json({ message: 'Post muted' });
  } catch (error) {
    console.error('Mute post error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Unmute a post
app.delete('/api/posts/:id/mute', authenticateToken, async (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id;

  try {
    const parsedPostId = parseInt(postId, 10);
    if (isNaN(parsedPostId)) {
      return res.status(400).json({ message: 'Invalid post ID' });
    }

    await pool.query(
      'DELETE FROM muted_posts WHERE user_id = $1 AND post_id = $2',
      [userId, parsedPostId]
    );

    res.status(200).json({ message: 'Post unmuted' });
  } catch (error) {
    console.error('Unmute post error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Check mute status
app.get('/api/posts/:id/mute', authenticateToken, async (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id;

  try {
    const parsedPostId = parseInt(postId, 10);
    if (isNaN(parsedPostId)) {
      return res.status(400).json({ message: 'Invalid post ID' });
    }

    const result = await pool.query(
      'SELECT EXISTS (SELECT 1 FROM muted_posts WHERE user_id = $1 AND post_id = $2) AS is_muted',
      [userId, parsedPostId]
    );

    res.status(200).json({ isMuted: result.rows[0].is_muted });
  } catch (error) {
    console.error('Check mute status error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Test route
app.get('/api/test', (req, res) => {
  res.send('Backend is alive!');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 
