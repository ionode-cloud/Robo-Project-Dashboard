require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');

const app = express();
app.get('/favicon.ico', (req, res) => res.status(204).end());
app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (mobile apps, etc.)
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
            'http://127.0.0.1:5501',
            'http://localhost:5501',
            'https://robo-dashboard-kohl.vercel.app'  
        ];
        
        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        } else {
            console.log('Blocked CORS origin:', origin);  // Log for Render debugging
            return callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.static('public'));

// MongoDB Connection - SILENT
mongoose.connect(process.env.MONGO_URI);

//  PROJECTS (Public - No login required)
const projectSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String, default: '' }, 
    frontendUrls: [String],
    backendUrls: [String],
    createdAt: { type: Date, default: Date.now }
});
const Project = mongoose.model('Project', projectSchema);

app.get('/api/projects', async (req, res) => {
    try {
        const projects = await Project.find().sort({ createdAt: -1 });
        res.json(projects);
    } catch (error) {
        res.status(500).json({ success: false, msg: 'Failed to fetch projects' });
    }
});

app.post('/api/projects', async (req, res) => {
    try {
        const project = new Project({
            name: req.body.name,
             description: req.body.description || '',
            frontendUrls: req.body.frontendUrls || [],
            backendUrls: req.body.backendUrls || []
        });
        await project.save();
        res.json({ success: true, project });
    } catch (error) {
        res.status(500).json({ success: false, msg: 'Failed to create project' });
    }
});

app.put('/api/projects/:id', async (req, res) => {
    try {
        const project = await Project.findByIdAndUpdate(
            req.params.id, 
            {
                name: req.body.name,
                description: req.body.description || '',  // ✅ UPDATE DESCRIPTION
                frontendUrls: req.body.frontendUrls || [],
                backendUrls: req.body.backendUrls || []
            }, 
            { new: true }
        );
        if (!project) return res.status(404).json({ success: false, msg: 'Project not found' });
        console.log('Project updated:', project.name);
        res.json({ success: true, project });
    } catch (error) {
        console.error('PUT /api/projects error:', error);
        res.status(500).json({ success: false, msg: 'Failed to update project' });
    }
});

app.delete('/api/projects/:id', async (req, res) => {
    try {
        const project = await Project.findByIdAndDelete(req.params.id);
        if (!project) return res.status(404).json({ success: false, msg: 'Project not found' });
        res.json({ success: true, msg: 'Project deleted' });
    } catch (error) {
        res.status(500).json({ success: false, msg: 'Failed to delete project' });
    }
});

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    otp: String,
    otpExpires: Date
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

const transporter = nodemailer.createTransport({
    host: "smtp.resend.com",
    port: 587,
    secure: false, 
    auth: {
        user: process.env.RESEND_API_KEY ,  
        pass: process.env.RESEND_API_KEY  
    },
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ success: false, msg: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-super-secret-key');
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ success: false, msg: 'Invalid token' });
    }
};
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, msg: 'Email and password required' });
        }

        const user = await User.findOne({ email });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(400).json({ success: false, msg: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { id: user._id, email: user.email }, 
            process.env.JWT_SECRET || 'your-super-secret-key', 
            { expiresIn: '24h' }
        );

        res.json({ 
            success: true, 
            token, 
            user: { id: user._id, email: user.email } 
        });
    } catch (error) {
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

// GET /api/auth/login - Health check (returns login form info)
app.get('/api/auth/login', (req, res) => {
    res.json({ 
        success: true, 
        msg: 'Login endpoint ready',
        requires: ['email', 'password'],
        method: 'POST'
    });
});

// POST /api/auth/login - Your existing login (unchanged)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, msg: 'Email and password required' });
        }

        const user = await User.findOne({ email });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(400).json({ success: false, msg: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { id: user._id, email: user.email }, 
            process.env.JWT_SECRET || 'your-super-secret-key', 
            { expiresIn: '24h' }
        );

        res.json({ 
            success: true, 
            token, 
            user: { id: user._id, email: user.email } 
        });
    } catch (error) {
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.json({ success: false, msg: 'If email exists, OTP sent!' }); // Don't reveal if user exists
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = otp;
        user.otpExpires = Date.now() + 10 * 60 * 1000;
        await user.save();

        // ✅ PRODUCTION DETECTION
        const isProduction = process.env.NODE_ENV === 'production';
        
        if (isProduction && process.env.RESEND_API_KEY) {
            // Resend for production
            await transporter.sendMail({
                from: '"ROBO Dashboard" <noreply@your-resend-domain.com>',
                to: email,
                subject: 'Password Reset OTP',
                html: `<h2>OTP: <strong style="font-size:28px;color:#3b82f6">${otp}</strong></h2>`
            });
        } else {
            // Gmail fallback (local/dev)
            await transporter.sendMail({
                from: process.env.GMAIL_USER,
                to: email,
                subject: 'Password Reset OTP - ROBO Dashboard',
                html: `<div style="font-family:Arial"><h2>OTP: <strong style="font-size:24px;color:#3b82f6">${otp}</strong></h2><p>Valid 10 min</p></div>`
            });
        }

        console.log(`OTP ${otp} sent to ${email}`);
        res.json({ success: true, msg: 'Check your email for OTP!' });
    } catch (error) {
        console.error('OTP ERROR:', error.message);
        res.status(500).json({ success: false, msg: 'Email service temporarily unavailable' });
    }
});

app.get('/api/auth/verify', authenticateToken, (req, res) => {
    res.json({ success: true, msg: 'Token valid', user: req.user });
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        const user = await User.findOne({ email });

        if (!user || user.otp !== otp || user.otpExpires < Date.now()) {
            return res.status(400).json({ success: false, msg: 'Invalid or expired OTP' });
        }

        res.json({ success: true, msg: 'OTP verified successfully' });
    } catch (error) {
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user || user.otpExpires < Date.now()) {
            return res.status(400).json({ success: false, msg: 'Invalid reset session' });
        }

        user.password = await bcrypt.hash(password, 12);
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();

        res.json({ success: true, msg: 'Password reset successfully' });
    } catch (error) {
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

app.get('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json({ success: true, user });
    } catch (error) {
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

app.get('/api/test', (req, res) => {
    res.json({ success: true, msg: 'Server working!' });
});

async function createTestUser() {
    try {
        const exists = await User.findOne({ email: 'ionodecloud@gmail.com' });
        if (!exists) {
            await User.create({
                email: 'ionodecloud@gmail.com',
                password: await bcrypt.hash('password123', 12)
            });
        }
    } catch (error) {
    }
}
createTestUser();

const PORT = process.env.PORT || 5555;
app.listen(PORT, () => {
    
});
