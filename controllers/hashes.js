const VirusHash = require('../models/VirusHash');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = path.join(__dirname, '..', 'uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, 'virus_' + Date.now() + '.txt');
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 },
    fileFilter: function (req, file, cb) {
        if (file.mimetype === 'text/plain' || file.originalname.endsWith('.txt')) {
            cb(null, true);
        } else {
            cb(new Error('Faqat .txt fayllar qabul qilinadi!'), false);
        }
    }
}).single('virusFile');

const getHashes = async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;

        const hashes = await VirusHash.find()
            .select('hash addedAt createdAt')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .lean();

        const totalHashes = await VirusHash.countDocuments();

        const totalPages = Math.ceil(totalHashes / limit);
        const hasNextPage = page < totalPages;
        const hasPrevPage = page > 1;

        res.status(200).json({
            success: true,
            data: {
                hashes,
                pagination: {
                    currentPage: page,
                    totalPages,
                    totalHashes,
                    hasNextPage,
                    hasPrevPage,
                    limit,
                    startIndex: skip + 1,
                    endIndex: Math.min(skip + limit, totalHashes)
                }
            }
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            message: 'Hashlarni olishda xatolik yuz berdi',
            error: error.message 
        });
    }
};

const getHashCount = async (req, res) => {
    try {
        const count = await VirusHash.countDocuments();
        
        res.status(200).json({
            success: true,
            data: {
                totalHashes: count,
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Hash sonini olishda xatolik yuz berdi',
            error: error.message
        });
    }
};

const getHashByHash = async (req, res) => { 
    try {
        const hash = req.params.hash;
        const hashData = await VirusHash.findOne({ hash });
        
        if (!hashData) {
            return res.status(404).json({
                success: false,
                message: 'Hash topilmadi'
            });
        }

        res.status(200).json({
            success: true,
            data: hashData
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Hash topilmadi',
            error: error.message
        });
    }
};

const addHash = async (req, res) => {
    try {
        const { hash } = req.body;
        
        if (!hash || hash.trim().length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Hash kiritilmagan'
            });
        }

        const trimmedHash = hash.trim();
        
        const existingHash = await VirusHash.findOne({ hash: trimmedHash });
        if (existingHash) {
            return res.status(400).json({
                success: false,
                message: 'Bu hash allaqachon mavjud'
            });
        }

        const newHash = await VirusHash.create({ hash: trimmedHash });
        
        res.status(201).json({
            success: true,
            message: 'Hash muvaffaqiyatli qo\'shildi',
            data: newHash
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Hash qo\'shishda xatolik yuz berdi',
            error: error.message
        });
    }
};

const deleteHash = async (req, res) => {
    try {
        const { id } = req.params;
        
        const hash = await VirusHash.findByIdAndDelete(id);
        
        if (!hash) {
            return res.status(404).json({
                success: false,
                message: 'Hash topilmadi'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Hash muvaffaqiyatli o\'chirildi'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Hash o\'chirishda xatolik yuz berdi',
            error: error.message
        });
    }
};

const searchHashes = async (req, res) => {
    try {
        const { q } = req.query;
        
        if (!q || q.trim().length < 3) {
            return res.status(400).json({
                success: false,
                message: 'Qidiruv uchun kamida 3 belgi kiriting'
            });
        }

        const hashes = await VirusHash.find({
            hash: { $regex: q.trim(), $options: 'i' }
        })
        .select('hash addedAt createdAt')
        .sort({ createdAt: -1 })
        .limit(50)
        .lean();

        res.status(200).json({
            success: true,
            data: {
                hashes,
                searchTerm: q.trim(),
                totalFound: hashes.length
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Qidiruvda xatolik yuz berdi',
            error: error.message
        });
    }
};


const uploadVirusFile = async (req, res) => {
    upload(req, res, async function(err) {
        if (err) {
            return res.status(400).json({
                success: false,
                message: err.message
            });
        }

        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'Fayl tanlanmagan'
            });
        }

        try {
            const filePath = req.file.path;
            const fileContent = fs.readFileSync(filePath, 'utf8');
            
            const hashes = fileContent
                .split('\n')
                .map(hash => hash.trim())
                .filter(hash => hash.length > 0 && hash.length >= 32);

            console.log(`${hashes.length} ta hash topildi`);

            let newHashes = 0;
            let existingHashes = 0;
            let errors = 0;
            let processedHashes = 0;

            res.writeHead(200, {
                'Content-Type': 'text/plain',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive'
            });

            const batchSize = 1000;
            const totalBatches = Math.ceil(hashes.length / batchSize);
            
            for (let i = 0; i < hashes.length; i += batchSize) {
                const batch = hashes.slice(i, i + batchSize);
                const currentBatch = Math.floor(i / batchSize) + 1;
                
                const existingBatch = await VirusHash.find({
                    hash: { $in: batch }
                }).select('hash');

                const existingHashSet = new Set(existingBatch.map(h => h.hash));
                const newBatch = batch.filter(hash => !existingHashSet.has(hash));

                if (newBatch.length > 0) {
                    try {
                        await VirusHash.insertMany(
                            newBatch.map(hash => ({ hash })),
                            { ordered: false }
                        );
                        newHashes += newBatch.length;
                    } catch (error) {
                        if (error.code === 11000) {
                            const duplicateErrors = error.writeErrors || [];
                            newHashes += newBatch.length - duplicateErrors.length;
                            existingHashes += duplicateErrors.length;
                        } else {
                            errors += newBatch.length;
                        }
                    }
                }
                
                existingHashes += batch.length - newBatch.length;
                processedHashes += batch.length;
                
                const progress = Math.round((processedHashes / hashes.length) * 100);
                const progressData = {
                    progress: progress,
                    processed: processedHashes,
                    total: hashes.length,
                    currentBatch: currentBatch,
                    totalBatches: totalBatches,
                    newHashes: newHashes,
                    existingHashes: existingHashes,
                    errors: errors
                };
                
                res.write(`data: ${JSON.stringify(progressData)}\n\n`);
                
                if (hashes.length > 5000) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }
            }

            fs.unlinkSync(filePath);

            const finalResult = {
                success: true,
                message: 'Fayl muvaffaqiyatli yuklandi',
                data: {
                    totalHashes: hashes.length,
                    newHashes,
                    existingHashes,
                    errors,
                    progress: 100
                },
                completed: true
            };

            res.write(`data: ${JSON.stringify(finalResult)}\n\n`);
            res.end();

        } catch (error) {
            if (req.file && fs.existsSync(req.file.path)) {
                fs.unlinkSync(req.file.path);
            }

            console.error('File upload error:', error);
            const errorResult = {
                success: false,
                message: 'Fayl yuklashda xatolik yuz berdi',
                error: error.message,
                completed: true
            };

            res.write(`data: ${JSON.stringify(errorResult)}\n\n`);
            res.end();
        }
    });
};

module.exports = {
    getHashes,
    getHashCount,
    getHashByHash,
    addHash,
    deleteHash,
    searchHashes,
    uploadVirusFile
}; 