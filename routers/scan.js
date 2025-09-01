const express = require('express');
const router = express.Router();
const { scanFile, scanUrl, getScanHistory, getFileHashStatus, checkUrlSimple, analyzeUrlWithBrowser } = require('../controllers/scan');

router.post('/file', scanFile);

router.post('/url', scanUrl);

router.get('/history', getScanHistory);

router.get('/file/:hash', getFileHashStatus);

router.get('/url/:url', checkUrlSimple);

router.get('/analyze-url/:url', analyzeUrlWithBrowser);

module.exports = router; 