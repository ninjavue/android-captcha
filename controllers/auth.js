const bcrypt = require('bcryptjs');
const Admin = require('../models/Admin');

const login = async (req, res) => {
    try {
        const { username, password } = req.body;

        const admin = await Admin.findOne({ username: username });
        console.log(admin)
        
        if (!admin) {
            return res.render('login', { 
                title: 'Kirish',
                error: 'Foydalanuvchi topilmadi!' 
            });
        }

        const isValidPassword = await admin.comparePassword(password);
        
        if (isValidPassword) {
            req.session.user = {
                id: admin._id,
                username: admin.username,
                isAuthenticated: true
            };
            
            res.redirect('/dashboard');
        } else {
            res.render('login', { 
                title: 'Kirish',
                error: 'Noto\'g\'ri parol!' 
            });
        }
    } catch (error) {
        console.error('Login xatolik:', error);
        res.render('login', { 
            title: 'Kirish',
            error: 'Tizim xatoligi yuz berdi!' 
        });
    }
};

const logout = (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout xatolik:', err);
        }
        res.redirect('/login');
    });
};

const requireAuth = (req, res, next) => {
    if (req.session.user && req.session.user.isAuthenticated) {
        next();
    } else {
        res.redirect('/login');
    }
};


module.exports = {
    login,
    logout,
    requireAuth
}; 