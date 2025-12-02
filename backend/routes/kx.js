const express = require('express');
const jwt = require('jsonwebtoken');

const router = express.Router();

// Simple in-memory message store for demo purposes
// In a real system you would persist this in MongoDB
const kxMessages = [];

// Authentication middleware (verifies JWT from Authorization header)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  if (!authHeader) {
    return res.status(401).json({ error: 'Missing Authorization header' });
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Invalid Authorization header' });
  }

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || 'default-secret-change-in-production'
    );
    req.user = decoded;
    next();
  } catch (err) {
    console.error('[KX] JWT verification error:', err);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Send key-exchange-related message to another user
router.post('/send', authenticateToken, (req, res) => {
  try {
    const { to, messageType, payload } = req.body;

    if (!to || !messageType || !payload) {
      return res.status(400).json({
        error: 'to, messageType, and payload are required'
      });
    }

    const msg = {
      id: Date.now().toString() + Math.random().toString(16).slice(2),
      from: req.user.username,
      to,
      messageType,
      payload,
      createdAt: new Date().toISOString()
    };

    kxMessages.push(msg);

    console.log(
      `[KX] Message queued: type=${messageType}, from=${msg.from}, to=${to}, at=${msg.createdAt}`
    );

    return res.json({ message: 'Message sent', id: msg.id });
  } catch (error) {
    console.error('[KX] Send error:', error);
    return res.status(500).json({ error: 'Internal server error in /kx/send' });
  }
});

// Fetch and clear all pending messages for the authenticated user
router.get('/inbox', authenticateToken, (req, res) => {
  try {
    const username = req.user.username;
    const usernameLower = typeof username === 'string' ? username.toLowerCase() : username;

    // Match messages case-insensitively on username to avoid issues with name casing
    const userMessages = kxMessages.filter((m) => {
      if (!m.to || typeof m.to !== 'string') return false;
      return m.to.toLowerCase() === usernameLower;
    });
    // Remove delivered messages from the in-memory store
    for (const msg of userMessages) {
      const idx = kxMessages.findIndex((m) => m.id === msg.id);
      if (idx !== -1) {
        kxMessages.splice(idx, 1);
      }
    }

    if (userMessages.length > 0) {
      console.log(
        `[KX] Delivering ${userMessages.length} message(s) to ${username} at ${new Date().toISOString()}`
      );
    }

    return res.json({ messages: userMessages });
  } catch (error) {
    console.error('[KX] Inbox error:', error);
    return res.status(500).json({ error: 'Internal server error in /kx/inbox' });
  }
});

module.exports = router;


