const VirusHash = require('../models/VirusHash');

const getDashboard = async (req, res) => {
    try {
        const totalHashes = await VirusHash.countDocuments();
        
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const todayAdded = await VirusHash.countDocuments({
            createdAt: { $gte: today }
        });
        
        const lastWeek = new Date();
        lastWeek.setDate(lastWeek.getDate() - 7);
        const lastWeekCount = await VirusHash.countDocuments({
            createdAt: { $gte: lastWeek }
        });
        
        const lastMonth = new Date();
        lastMonth.setMonth(lastMonth.getMonth() - 1);
        const lastMonthCount = await VirusHash.countDocuments({
            createdAt: { $gte: lastMonth }
        });
        
        const recentHashes = await VirusHash.find()
            .sort({ createdAt: -1 })
            .limit(10)
            .select('hash createdAt addedAt')
            .lean(); 
        
        const chartData = [];
        const chartLabels = [];
        
        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            date.setHours(0, 0, 0, 0);
            
            const nextDate = new Date(date);
            nextDate.setDate(nextDate.getDate() + 1);
            
            const count = await VirusHash.countDocuments({
                createdAt: { $gte: date, $lt: nextDate }
            });
            
            chartData.push(count);
            chartLabels.push(date.toLocaleDateString('uz-UZ', { month: 'short', day: 'numeric' }));
        }
        
        res.render('dashboard', {
            title: 'Dashboard',
            totalHashes,
            todayAdded,
            lastWeek: lastWeekCount,
            lastMonth: lastMonthCount,
            recentHashes,
            chartLabels: JSON.stringify(chartLabels),
            chartData: JSON.stringify(chartData)
        });
        
    } catch (error) {
        console.error('Dashboard xatolik:', error);
        res.status(500).render('error', {
            title: 'Xatolik',
            message: 'Dashboard ma\'lumotlarini yuklashda xatolik yuz berdi'
        });
    }
};

const getDashboardStats = async (req, res) => {
    try {
        const totalHashes = await VirusHash.countDocuments();
        
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const todayAdded = await VirusHash.countDocuments({
            createdAt: { $gte: today }
        });
        
        const lastWeek = new Date();
        lastWeek.setDate(lastWeek.getDate() - 7);
        const lastWeekCount = await VirusHash.countDocuments({
            createdAt: { $gte: lastWeek }
        });
        
        const lastMonth = new Date();
        lastMonth.setMonth(lastMonth.getMonth() - 1);
        const lastMonthCount = await VirusHash.countDocuments({
            createdAt: { $gte: lastMonth }
        });
        
        res.json({
            success: true,
            data: {
                totalHashes,
                todayAdded,
                lastWeek: lastWeekCount,
                lastMonth: lastMonthCount
            }
        });
        
    } catch (error) {
        console.error('Stats xatolik:', error);
        res.status(500).json({
            success: false,
            message: 'Statistikalar yuklanmadi'
        });
    }
};

module.exports = {
    getDashboard,
    getDashboardStats
}; 