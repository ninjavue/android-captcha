const mongoose = require('mongoose');

const maliciousUrlSchema = new mongoose.Schema({
    url: {
        type: String,
        required: true,
        unique: true
    },
    hash: {
        type: String,
        required: true
    },
    threatLevel: {
        type: String,
        enum: ['Past', 'O\'rta', 'Yuqori'],
        default: 'Yuqori'
    },
    vtResult: {
        type: String,
        default: 'N/A'
    },
    addedAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('MaliciousUrl', maliciousUrlSchema); 