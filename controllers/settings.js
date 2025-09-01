const Admin = require('../models/Admin');

exports.changePassword = async (req, res) => {
    try {
        const { oldPassword, newPassword, confirmPassword } = req.body;
        if (!oldPassword || !newPassword || !confirmPassword) {
            return res.json({ success: false, message: 'Barcha maydonlarni to\'ldiring.' });
        }
        if (newPassword !== confirmPassword) {
            return res.json({ success: false, message: 'Yangi parollar mos emas.' });
        }
        if (newPassword.length < 6) {
            return res.json({ success: false, message: 'Yangi parol kamida 6 ta belgidan iborat bo\'lishi kerak.' });
        }

        const admin = await Admin.findOne({ username: 'admin' });
        if (!admin) return res.json({ success: false, message: 'Admin topilmadi.' });

        const isMatch = await admin.comparePassword(oldPassword);
        if (!isMatch) {
            return res.json({ success: false, message: 'Eski parol noto\'g\'ri.' });
        }

        admin.password = newPassword;
        await admin.save();

        res.json({ success: true, message: 'Parol muvaffaqiyatli o\'zgartirildi.' });
    } catch (error) {
        res.json({ success: false, message: 'Xatolik: ' + error.message });
    }
};