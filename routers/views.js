const express = require('express');
const router = express.Router();
const { requireAuth } = require('../controllers/auth');
const { getDashboard } = require('../controllers/dashboard');
const { getHashes } = require('../controllers/hashes');

router.get('/login', (req, res) => {
    if (req.session.user && req.session.user.isAuthenticated) {
        res.redirect('/dashboard');
    } else {
        res.render('login', { title: 'Kirish' });
    }
});

router.get('/dashboard', requireAuth, getDashboard);

router.get('/hashes', requireAuth, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;

        const hashes = await require('../models/VirusHash').find()
            .select('hash addedAt createdAt')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .lean();

        const totalHashes = await require('../models/VirusHash').countDocuments();
        
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const todayAdded = await require('../models/VirusHash').countDocuments({
            createdAt: { $gte: today }
        });
        
        const lastWeek = new Date();
        lastWeek.setDate(lastWeek.getDate() - 7);
        const lastWeekCount = await require('../models/VirusHash').countDocuments({
            createdAt: { $gte: lastWeek }
        });
        
        const lastMonth = new Date();
        lastMonth.setMonth(lastMonth.getMonth() - 1);
        const lastMonthCount = await require('../models/VirusHash').countDocuments({
            createdAt: { $gte: lastMonth }
        });

        res.render('hashes', {
            title: 'Hashlar',
            hashes,
            totalHashes,
            todayAdded,
            lastWeek: lastWeekCount,
            lastMonth: lastMonthCount
        });
    } catch (error) {
        console.error('Hashlar sahifasi xatolik:', error);
        res.status(500).render('error', {
            title: 'Xatolik',
            message: 'Hashlar sahifasini yuklashda xatolik yuz berdi'
        });
    }
});

router.get('/scan', requireAuth, (req, res) => {
    res.render('scan', { title: 'Fayl va URL Tekshirish' });
});

router.get('/settings', requireAuth, async (req, res) => {
    const Admin = require('../models/Admin');
    const admin = await Admin.findOne({ username: 'admin' });
    let passwordChangeRequired = false;
    if (admin && await admin.comparePassword('admin123')) {
        passwordChangeRequired = true;
    }
    res.render('settings', { title: 'Sozlamalar', passwordChangeRequired });
});

router.get('/', (req, res) => {
    if (req.session.user && req.session.user.isAuthenticated) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login');
    }
});

module.exports = router; 