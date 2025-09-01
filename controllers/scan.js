const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');
const ScanHistory = require('../models/ScanHistory');
const MaliciousUrl = require('../models/MaliciousUrl');
const VirusHash = require('../models/VirusHash');
const CleanHash = require('../models/CleanHash');
const puppeteer = require('puppeteer');

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = path.join(__dirname, '..', 'uploads', 'scan');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, 'scan_' + Date.now() + '_' + file.originalname);
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 32 * 1024 * 1024 
    }
}).single('scanFile');

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY
const VIRUSTOTAL_API_KEY_URL = process.env.VIRUSTOTAL_API_KEY_URL
const VIRUSTOTAL_BASE_URL = 'https://www.virustotal.com/vtapi/v2';

function calculateMD5(filePath) {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash('md5');
        const stream = fs.createReadStream(filePath);
        
        stream.on('data', (data) => {
            hash.update(data);
        });
        
        stream.on('end', () => {
            resolve(hash.digest('hex'));
        });
        
        stream.on('error', (error) => {
            reject(error);
        });
    });
}

async function checkHashWithVirusTotal(hash) {
    try {
        const response = await axios.get(`${VIRUSTOTAL_BASE_URL}/file/report`, {
            params: {
                apikey: VIRUSTOTAL_API_KEY,
                resource: hash
            }
        });
        
        if (response.data.response_code === 1) {
            const positives = response.data.positives;
            const total = response.data.total;
            const ratio = positives / total;
            
            let threatLevel = 'Past';
            if (ratio > 0.1) {
                threatLevel = 'Yuqori';
            } else if (ratio > 0.05) {
                threatLevel = 'O\'rta';
            }
            
            return {
                malicious: positives > 0,
                vtResult: `${positives}/${total} antivirus dasturlari zararli deb topdi`,
                threatLevel: threatLevel
            };
        } else {
            return {
                malicious: false,
                vtResult: 'Hash VirusTotal bazasida topilmadi',
                threatLevel: 'Past'
            };
        }
    } catch (error) {
        console.error('VirusTotal API error:', error.message);
        return {
            malicious: false,
            vtResult: 'VirusTotal API bilan bog\'lanishda xatolik',
            threatLevel: 'Past'
        };
    }
}

async function checkUrlWithVirusTotal(url) {
    try {
        const form = new URLSearchParams();
        form.append('apikey', VIRUSTOTAL_API_KEY_URL);
        form.append('url', url);

        const response = await axios.post(
            `${VIRUSTOTAL_BASE_URL}/url/scan`,
            form.toString(),
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );

        await new Promise(resolve => setTimeout(resolve, 2000));
        const scanId = response.data.scan_id || url;

        const reportResponse = await axios.get(`${VIRUSTOTAL_BASE_URL}/url/report`, {
            params: {
                apikey: VIRUSTOTAL_API_KEY,
                resource: scanId
            }
        });

        if (reportResponse.data.response_code === 1) {
            const positives = reportResponse.data.positives;
            const total = reportResponse.data.total;
            const ratio = positives / total;

            let threatLevel = 'Past';
            if (ratio > 0.1) {
                threatLevel = 'Yuqori';
            } else if (ratio > 0.05) {
                threatLevel = 'O\'rta';
            }

            return {
                malicious: positives > 0,
                vtResult: `${positives}/${total} antivirus dasturlari zararli deb topdi`,
                threatLevel: threatLevel
            };
        } else {
            return {
                malicious: false,
                vtResult: 'URL VirusTotal bazasida topilmadi',
                threatLevel: 'Past'
            };
        }
    } catch (error) {
        console.error('VirusTotal URL API error:', error.message);
        return {
            malicious: false,
            vtResult: 'VirusTotal API bilan bog\'lanishda xatolik',
            threatLevel: 'Past'
        };
    }
}



const scanFile = async (req, res) => {
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
            const filename = req.file.originalname;
            
            const hash = await calculateMD5(filePath);
            
            const existingHash = await VirusHash.findOne({ hash });
            if (existingHash) {
                fs.unlinkSync(filePath);
                
                return res.status(200).json({
                    success: true,
                    data: {
                        hash: hash,
                        malicious: true,
                        vtResult: 'Hash bazada mavjud (zararli)',
                        threatLevel: 'Yuqori',
                        addedToDatabase: true
                    }
                });
            }
            
            const vtResult = await checkHashWithVirusTotal(hash);
            
            let addedToDatabase = false;
            if (vtResult.malicious) {
                try {
                    await VirusHash.create({ hash });
                    addedToDatabase = true;
                } catch (error) {
                    console.error('Hash qo\'shishda xatolik:', error);
                }
            }
            
            await ScanHistory.create({
                type: 'file',
                filename: filename,
                hash: hash,
                malicious: vtResult.malicious,
                vtResult: vtResult.vtResult,
                threatLevel: vtResult.threatLevel,
                addedToDatabase: addedToDatabase
            });
            
            fs.unlinkSync(filePath);
            
            res.status(200).json({
                success: true,
                data: {
                    hash: hash,
                    malicious: vtResult.malicious,
                    vtResult: vtResult.vtResult,
                    threatLevel: vtResult.threatLevel,
                    addedToDatabase: addedToDatabase
                }
            });

        } catch (error) {
            if (req.file && fs.existsSync(req.file.path)) {
                fs.unlinkSync(req.file.path);
            }

            console.error('File scan error:', error);
            res.status(500).json({
                success: false,
                message: 'Fayl tekshirishda xatolik yuz berdi',
                error: error.message
            });
        }
    });
};

const scanUrl = async (req, res) => {
    try {
        const { url } = req.body;
        
        if (!url) {
            return res.status(400).json({
                success: false,
                message: 'URL kiritilmagan'
            });
        }
        
        const existingUrl = await MaliciousUrl.findOne({ url });
        if (existingUrl) {
            return res.status(200).json({
                success: true,
                data: {
                    hash: existingUrl.hash,
                    malicious: true,
                    vtResult: 'URL bazada mavjud (zararli)',
                    threatLevel: existingUrl.threatLevel,
                    addedToDatabase: true
                }
            });
        }
        
        const hash = crypto.createHash('md5').update(url).digest('hex');
        
        const vtResult = await checkUrlWithVirusTotal(url);
        
        let addedToDatabase = false;
        if (vtResult.malicious) {
            try {
                await MaliciousUrl.create({
                    url: url,
                    hash: hash,
                    threatLevel: vtResult.threatLevel,
                    vtResult: vtResult.vtResult
                });
                addedToDatabase = true;
            } catch (error) {
                console.error('URL qo\'shishda xatolik:', error);
            }
        }
        
        await ScanHistory.create({
            type: 'url',
            url: url,
            hash: hash,
            malicious: vtResult.malicious,
            vtResult: vtResult.vtResult,
            threatLevel: vtResult.threatLevel,
            addedToDatabase: addedToDatabase
        });
        
        res.status(200).json({
            success: true,
            data: {
                hash: hash,
                malicious: vtResult.malicious,
                vtResult: vtResult.vtResult,
                threatLevel: vtResult.threatLevel,
                addedToDatabase: addedToDatabase
            }
        });

    } catch (error) {
        console.error('URL scan error:', error);
        res.status(500).json({
            success: false,
            message: 'URL tekshirishda xatolik yuz berdi',
            error: error.message
        });
    }
};

const getScanHistory = async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;

        const history = await ScanHistory.find()
            .sort({ scannedAt: -1 })
            .skip(skip)
            .limit(limit)
            .lean();

        const totalScans = await ScanHistory.countDocuments();

        res.status(200).json({
            success: true,
            data: history,
            pagination: {
                currentPage: page,
                totalPages: Math.ceil(totalScans / limit),
                totalScans,
                hasNextPage: page < Math.ceil(totalScans / limit),
                hasPrevPage: page > 1
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Scan tarixini olishda xatolik yuz berdi',
            error: error.message
        });
    }
};

const getFileHashStatus = async (req, res) => {
    const { hash } = req.params;
    if (!hash || hash.length < 8) {
        return res.status(400).json({ success: false, message: 'Hash noto\'g\'ri' });
    }
    try {
        const virus = await VirusHash.findOne({ hash });
        if (virus) {
            return res.json({ success: true, status: 'virus', source: 'local', message: 'Virusli fayl' });
        }
        const clean = await CleanHash.findOne({ hash });
        if (clean) {
            const now = new Date();
            const diffMs = now - clean.createdAt;
            const diffDays = diffMs / (1000 * 60 * 60 * 24);
            if (diffDays > 3) {
                return res.json({ success: true, status: 'clean', source: 'local', message: 'Toza fayl (3 kundan ko\'p)' });
            }
        }
        const vt = await checkHashWithVirusTotal(hash);
        if (vt.malicious) {
            await VirusHash.create({ hash });
            return res.json({ success: true, status: 'virus', source: 'virustotal', vtResult: vt.vtResult, threatLevel: vt.threatLevel });
        } else {
            await CleanHash.findOneAndUpdate(
                { hash },
                { hash, createdAt: new Date() },
                { upsert: true, new: true }
            );
            return res.json({ success: true, status: 'clean', source: 'virustotal', vtResult: vt.vtResult, threatLevel: vt.threatLevel });
        }
    } catch (error) {
        console.error('getFileHashStatus error:', error);
        return res.status(500).json({ success: false, message: 'Server xatoligi', error: error.message });
    }
};

const checkUrlSimple = (req, res) => {
    let { url } = req.params;
    if (!url) {
        return res.status(400).json({ success: false, message: 'URL kiritilmagan' });
    }

    url = decodeURIComponent(url);
    
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
    }

    let parsedUrl;
    try {
        parsedUrl = new URL(url);
    } catch (error) {
        return res.status(400).json({ success: false, message: 'Noto\'g\'ri URL format' });
    }

    const hostname = parsedUrl.hostname.toLowerCase();
    const pathname = parsedUrl.pathname.toLowerCase();
    const fullUrl = url.toLowerCase();

    const badWords = ['phishing', 'malware', 'suspicious', 'virus', 'trojan', 'hack', 'exploit', 'attack', 'crack', 'keygen', 'warez', 'spam', 'scam'];
    
    const suspiciousTlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.cc', '.pw', '.club', '.online'];
    
    const maliciousDomains = ['malware.com', 'virus.ru', 'phishing.net', 'scam.org'];

    for (const domain of maliciousDomains) {
        if (hostname.includes(domain)) {
            return res.json({ 
                success: true, 
                status: 'malicious', 
                message: `Zararli domen: ${domain}`,
                details: { hostname, pathname }
            });
        }
    }

    for (const word of badWords) {
        if (pathname.includes(word) || parsedUrl.search.toLowerCase().includes(word)) {
            return res.json({ 
                success: true, 
                status: 'malicious', 
                message: `URL zararli so'z o'z ichiga oladi: ${word}`,
                details: { hostname, pathname, foundWord: word }
            });
        }
    }

    for (const tld of suspiciousTlds) {
        if (hostname.endsWith(tld)) {
            return res.json({ 
                success: true, 
                status: 'malicious', 
                message: `Shubhali domen: ${tld}`,
                details: { hostname, pathname, suspiciousTld: tld }
            });
        }
    }

    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    if (ipPattern.test(hostname)) {
        return res.json({ 
            success: true, 
            status: 'malicious', 
            message: 'URL IP manzil orqali (shubhali)',
            details: { hostname, pathname }
        });
    }

    if (parsedUrl.protocol === 'http:') {
        return res.json({ 
            success: true, 
            status: 'malicious', 
            message: 'URL faqat http protokoli orqali (xavfsiz emas)',
            details: { hostname, pathname, protocol: parsedUrl.protocol }
        });
    }

    return res.json({ 
        success: true, 
        status: 'clean', 
        message: 'URL zararsiz deb topildi',
        details: { hostname, pathname, protocol: parsedUrl.protocol }
    });
};

const analyzeUrlWithBrowser = async (req, res) => {
    let { url } = req.params;
    if (!url) {
        return res.status(400).json({ success: false, message: 'URL kiritilmagan' });
    }
    url = decodeURIComponent(url);
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'http://' + url;
    }

    let browser;
    try {
        browser = await puppeteer.launch({ 
            args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
            headless: true
        });
        const page = await browser.newPage();
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36');
        const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });

        const title = await page.title();
        const forms = await page.$$eval('form', forms => forms.length);
        const scripts = await page.$$eval('script', scripts => scripts.length);
        const iframes = await page.$$eval('iframe', iframes => iframes.length);
        const pageContent = await page.content();
        const finalUrl = page.url();
        const hostname = new URL(finalUrl).hostname;

        const whitelist = [
            'virustotal.com', 'google.com', 'github.com', 'amazon.com', 'microsoft.com', 'yandex.ru', 'gov.uz', 'edu.uz', 'kun.uz'
        ];
        if (whitelist.some(w => hostname === w || hostname.endsWith('.' + w))) {
            await browser.close();
            return res.json({
                success: true,
                status: 'clean',
                message: 'Ishonchli domen (whitelist)',
                details: { hostname }
            });
        }

        let sslInfo = null;
        let sslValid = true; 
        let sslIssuer = '';
        let sslError = '';
        if (finalUrl.startsWith('https://')) {
            try {
                const securityDetails = response.securityDetails && response.securityDetails();
                if (securityDetails) {
                    sslInfo = {
                        issuer: securityDetails.issuer(),
                        validFrom: securityDetails.validFrom(),
                        validTo: securityDetails.validTo(),
                        protocol: securityDetails.protocol()
                    };
                    sslIssuer = securityDetails.issuer();
                    console.log('SSL Issuer:', sslIssuer);
                    if (
                        sslIssuer.toLowerCase().includes('self-signed') ||
                        sslIssuer.toLowerCase().includes('invalid') ||
                        sslIssuer.toLowerCase().includes('unknown')
                    ) {
                        sslValid = false;
                    }
                } else {
                    sslError = 'SSL ma\'lumotlari olinmadi';
                    sslValid = true;
                }
            } catch (e) {
                sslError = 'SSL tekshiruvda xatolik: ' + e.message;
                sslValid = true;
            }
        }

        if (finalUrl.startsWith('http://')) {
            await browser.close();
            return res.json({
                success: true,
                status: 'malicious',
                message: 'HTTP protokoli xavfsiz emas',
                details: { hostname, protocol: 'http' }
            });
        }

        if (finalUrl.startsWith('https://') && !sslValid) {
            await browser.close();
            return res.json({
                success: true,
                status: 'malicious',
                message: 'SSL sertifikat ishonchsiz (self-signed, invalid yoki unknown)',
                details: { hostname, sslInfo, sslError }
            });
        }

        let suspiciousCount = 0;
        let reasons = [];

        if (forms > 0) {
            const formFields = await page.$$eval('form input', inputs =>
                inputs.map(input => input.type || input.name || input.id).join(' ').toLowerCase()
            );
            if (formFields.includes('password') || formFields.includes('pass') || formFields.includes('pwd')) {
                suspiciousCount++;
                reasons.push('Parol so\'raladigan forma mavjud');
            }
        }
        if (scripts > 20) {
            suspiciousCount++;
            reasons.push('Juda ko\'p JavaScript skriptlari mavjud');
        }
        if (iframes > 5) {
            suspiciousCount++;
            reasons.push('Ko\'p iframe\'lar mavjud (shubhali)');
        }
        const suspiciousWords = ['login', 'verify', 'secure', 'update', 'confirm', 'bank', 'paypal', 'amazon'];
        for (const word of suspiciousWords) {
            if (title.toLowerCase().includes(word)) {
                suspiciousCount++;
                reasons.push(`Sarlavhada shubhali so'z: ${word}`);
                break;
            }
        }
        const maliciousWords = ['phishing', 'malware', 'virus', 'trojan', 'hack', 'exploit', 'attack'];
        for (const word of maliciousWords) {
            if (pageContent.toLowerCase().includes(word)) {
                suspiciousCount++;
                reasons.push(`Kontentda zararli so'z: ${word}`);
                break;
            }
        }
        const redirects = finalUrl !== url;
        if (redirects) {
            suspiciousCount++;
            reasons.push('Sahifa boshqa URL\'ga yo\'naltirildi');
        }

        await browser.close();

        if (suspiciousCount >= 2) {
            return res.json({
                success: true,
                status: 'malicious',
                message: 'URL zararli deb topildi',
                details: { hostname, reasons, suspiciousCount }
            });
        } else {
            return res.json({
                success: true,
                status: 'clean',
                message: 'URL zararsiz deb topildi',
                details: { hostname, reasons, suspiciousCount }
            });
        }

    } catch (error) {
        if (browser) await browser.close();
        return res.status(500).json({
            success: false,
            message: 'URL tahlil qilishda xatolik',
            error: error.message
        });
    }
};

module.exports = {
    scanFile,
    scanUrl,
    getScanHistory,
    getFileHashStatus,
    checkUrlSimple,
    analyzeUrlWithBrowser
}; 