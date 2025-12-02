const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema(
  {
    sessionId: {
      type: String,
      required: true
    },
    from: {
      type: String,
      required: true,
      index: true
    },
    to: {
      type: String,
      required: true,
      index: true
    },
    ciphertext: {
      type: String,
      required: true
    },
    iv: {
      type: String,
      required: true
    },
    msgSeq: {
      type: Number,
      required: true
    },
    timestamp: {
      type: Date,
      default: Date.now
    }
  },
  {
    timestamps: true
  }
);

// Compound index to efficiently query a conversation
messageSchema.index({ sessionId: 1, from: 1, to: 1, msgSeq: 1 });

const Message = mongoose.model('Message', messageSchema);

module.exports = Message;


