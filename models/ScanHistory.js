const mongoose = require('mongoose');

const scanHistorySchema = new mongoose.Schema({
    type: {
        type: String,
        enum: ['file', 'url'],
        required: true
    },
    filename: {
        type: String,
        required: function() { return this.type === 'file'; }
    },
    url: {
        type: String,
        required: function() { return this.type === 'url'; }
    },
    hash: {
        type: String,
        required: true
    },
    malicious: {
        type: Boolean,
        default: false
    },
    vtResult: {
        type: String,
        default: 'N/A'
    },
    threatLevel: {
        type: String,
        enum: ['Past', 'O\'rta', 'Yuqori'],
        default: 'Past'
    },
    addedToDatabase: {
        type: Boolean,
        default: false
    },
    scannedAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('ScanHistory', scanHistorySchema); 