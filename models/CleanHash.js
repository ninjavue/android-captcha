const mongoose = require('mongoose');

const cleanHashSchema = new mongoose.Schema({
  hash: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

cleanHashSchema.index({ hash: 1 });

module.exports = mongoose.model('CleanHash', cleanHashSchema);