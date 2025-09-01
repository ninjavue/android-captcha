const mongoose = require('mongoose');

const virusHashSchema = new mongoose.Schema({
  hash: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  addedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

virusHashSchema.index({ hash: 1 });

module.exports = mongoose.model('VirusHash', virusHashSchema); 