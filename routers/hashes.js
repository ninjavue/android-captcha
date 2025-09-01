const express = require('express');
const router = express.Router();
const { 
    getHashes, 
    getHashCount, 
    getHashByHash, 
    addHash, 
    deleteHash, 
    searchHashes, 
    uploadVirusFile
} = require('../controllers/hashes');

router.get('/', getHashes);

router.get('/count', getHashCount);

router.get('/search', searchHashes);

router.get('/:hash', getHashByHash);

router.post('/', addHash);

router.post('/upload', uploadVirusFile);

router.delete('/:id', deleteHash);

module.exports = router;