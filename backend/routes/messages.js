const express = require('express');
const jwt = require('jsonwebtoken');
const Message = require('../models/Message');

const router = express.Router();

// Simple JWT auth middleware (same pattern as in kx.js)
const authenticateToken = (req, res, next) => {
  const header = req.headers['authorization'] || req.headers['Authorization'];
  if (!header) {
    return res.status(401).json({ error: 'Missing Authorization header' });
  }

  const token = header.split(' ')[1];
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
    console.error('[MSG] JWT verification error:', err);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Store a new encrypted message (ciphertext only)
router.post('/send', authenticateToken, async (req, res) => {
  try {
    const { sessionId, to, ciphertext, iv, msgSeq, timestamp } = req.body;

    if (!sessionId || !to || !ciphertext || !iv || typeof msgSeq !== 'number') {
      return res.status(400).json({
        error: 'sessionId, to, ciphertext, iv and numeric msgSeq are required'
      });
    }

    const from = req.user.username;

    const message = new Message({
      sessionId,
      from,
      to,
      ciphertext,
      iv,
      msgSeq,
      timestamp: timestamp ? new Date(timestamp) : new Date()
    });

    await message.save();

    console.log(
      `[MSG] Encrypted message stored: sessionId=${sessionId}, from=${from}, to=${to}, msgSeq=${msgSeq}`
    );

    return res.status(201).json({ message: 'Encrypted message stored' });
  } catch (error) {
    console.error('[MSG] Send error:', error);
    return res.status(500).json({ error: 'Internal server error in /messages/send' });
  }
});

// Get encrypted messages for a conversation (both directions)
router.get('/conversation/:peerUsername/:sessionId', authenticateToken, async (req, res) => {
  try {
    const me = req.user.username;
    const peer = req.params.peerUsername;
    const sessionId = req.params.sessionId;

    if (!peer || !sessionId) {
      return res.status(400).json({ error: 'peerUsername and sessionId are required' });
    }

    const criteria = {
      sessionId,
      $or: [
        { from: me, to: peer },
        { from: peer, to: me }
      ]
    };

    const messages = await Message.find(criteria).sort({ msgSeq: 1, timestamp: 1 }).lean();

    // Only return ciphertext + IV + metadata (no plaintext)
    const safeMessages = messages.map((m) => ({
      from: m.from,
      to: m.to,
      sessionId: m.sessionId,
      ciphertext: m.ciphertext,
      iv: m.iv,
      msgSeq: m.msgSeq,
      timestamp: m.timestamp
    }));

    console.log(
      `[MSG] Returning ${safeMessages.length} encrypted message(s) for conversation ${me}<->${peer}, sessionId=${sessionId}`
    );

    return res.json(safeMessages);
  } catch (error) {
    console.error('[MSG] Conversation error:', error);
    return res.status(500).json({ error: 'Internal server error in /messages/conversation' });
  }
});

module.exports = router;


