const express = require('express');
const cors = require('cors');
const session = require('express-session');
const exphbs = require('express-handlebars');
const path = require('path');
const connectDB = require('./database');
const loadVirusHashes = require('./utils/virusHashLoader');
require('dotenv').config();

const app = express();

const hbs = exphbs.create({
    extname: '.hbs',
    defaultLayout: 'main',
    helpers: {
        formatDate: function(date) {
            if (!date) return 'N/A';
            try {
                const d = new Date(date);
                if (isNaN(d.getTime())) return 'N/A';
                return d.toLocaleDateString('uz-UZ', {
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit'
                });
            } catch (error) {
                return 'N/A';
            }
        }
    }
});

app.engine('hbs', hbs.engine);
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
    secret: process.env.SESSION_SECRET || 'dafdsfjsdkfjslkafjkkljfsdf',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(cors({
  origin: '*', 
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

connectDB().then(() => {
  console.log(`MongoDB ulanish muvaffaqiyatli...`);
}).catch(err => {
  console.error('Database ulanishda xatolik:', err);
});

const viewsRouter = require('./routers/views');
const authRouter = require('./routers/auth');
const hashesRouter = require('./routers/hashes');
const scanRouter = require('./routers/scan');
const settingsRouter = require('./routers/settings');
const Admin = require('./models/Admin');
const { getDashboardStats } = require('./controllers/dashboard');

async function ensureDefaultAdmin() {
    const admin = await Admin.findOne({ username: 'admin' });
    if (!admin) {
        await Admin.create({ username: 'admin', password: 'admin123' });
        console.log('Admin muvaffaqiyatli yaratildi!');
    }
}
ensureDefaultAdmin();

app.use('/', viewsRouter);
app.use('/auth', authRouter);

app.use('/api/hashes', hashesRouter);
app.use('/api/scan', scanRouter);
app.use('/api/settings', settingsRouter);
app.get('/api/dashboard/stats', getDashboardStats);


const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server ${PORT} portda ishga tushdi...`);
  console.log(`Dashboard: http://localhost:${PORT}`);
});
