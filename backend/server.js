require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');
const RateLimit = require('express-rate-limit'); // Add this

const app = express();

// Rate limiting for forgot-password (prevents spam)
const forgotLimiter = RateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 3, // 3 requests per IP
    message: { success: false, msg: 'Too many forgot password requests, try again later' }
});

app.get('/favicon.ico', (req, res) => res.status(204).end());

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        const allowedOrigins = [
            'http://127.0.0.1:5501',
            'http://localhost:5501',
            'https://robo-dashboard-kohl.vercel.app',
            'https://robo-project-dashboard.onrender.com' 
        ];
        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        console.log('Blocked CORS origin:', origin);
        return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.static('public'));

mongoose.connect(process.env.MONGO_URI).then(() => {
    console.log('✅ MongoDB Connected');
}).catch(err => {
    console.error('❌ MongoDB Error:', err);
});

// ✅ CORRECT (this will work)
const transporter = nodemailer.createTransport({

    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS  // Use Gmail App Password!
    },
    tls: {
        rejectUnauthorized: false
    }
});


// Test transporter on startup (logs to Render console)
transporter.verify((error, success) => {
    if (error) {
        console.error('❌ Email transporter failed:', error);
    } else {
        console.log('✅ Email transporter ready');
    }
});

// Your existing Project routes (unchanged)...
const projectSchema = new mongoose.Schema({
    name: { type: String, required: true },
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
        const project = await Project.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!project) return res.status(404).json({ success: false, msg: 'Project not found' });
        res.json({ success: true, project });
    } catch (error) {
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

// User Schema (unchanged)
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    otp: String,
    otpExpires: Date
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

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

// FIXED: Better login with detailed logging
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('🔐 Login attempt for:', email); // Render logs
        
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
        console.error('Login error:', error);
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

// FIXED: Forgot password with detailed logging + rate limiting
app.post('/api/auth/forgot-password', forgotLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        console.log('📧 Forgot password for:', email); // Render logs
        
        const user = await User.findOne({ email });

        if (!user) {
            // Don't reveal if user exists (security)
            return res.json({ success: true, msg: 'If user exists, OTP sent to your email!' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = otp;
        user.otpExpires = Date.now() + 10 * 60 * 1000; // 10 min
        await user.save();

        console.log('🔢 Generated OTP:', otp); // Render logs (remove in prod if paranoid)

        // FIXED: Better email with error handling
        const mailOptions = {
            from: `"ROBO Dashboard" <${process.env.GMAIL_USER}>`,
            to: email,
            subject: 'Password Reset OTP - ROBO Dashboard',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #243946;">🔐 Password Reset OTP</h2>
                    <div style="background: #f0f9ff; padding: 20px; border-radius: 10px; border-left: 4px solid #3b82f6;">
                        <p><strong>Your 6-digit OTP:</strong></p>
                        <h1 style="font-size: 32px; color: #3b82f6; letter-spacing: 8px; margin: 10px 0;">${otp}</h1>
                        <p style="color: #666; font-size: 14px;">This OTP expires in <strong>10 minutes</strong>.</p>
                    </div>
                    <hr style="margin: 30px 0;">
                    <p>If you didn't request this, please ignore this email.</p>
                    <p style="color: #666; font-size: 12px;">ROBO Dashboard Team</p>
                </div>
            `
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('✅ OTP Email sent:', info.messageId); // Render logs

        res.json({ success: true, msg: 'OTP sent to your email!' });
        
    } catch (error) {
        console.error('❌ Forgot password error:', error.message);
        res.status(500).json({ success: false, msg: 'Failed to send OTP. Check your email spam folder.' });
    }
});

// Verify OTP (unchanged but with logging)
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        console.log('🔍 Verifying OTP for:', email);
        
        const user = await User.findOne({ email });

        if (!user || user.otp !== otp || user.otpExpires < Date.now()) {
            return res.status(400).json({ success: false, msg: 'Invalid or expired OTP' });
        }

        res.json({ success: true, msg: 'OTP verified successfully' });
    } catch (error) {
        console.error('Verify OTP error:', error);
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

// Reset password (unchanged but with logging)
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('🔄 Resetting password for:', email);
        
        const user = await User.findOne({ email });

        if (!user || user.otpExpires < Date.now()) {
            return res.status(400).json({ success: false, msg: 'Invalid reset session' });
        }

        user.password = await bcrypt.hash(password, 12);
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();

        console.log('✅ Password reset successful');
        res.json({ success: true, msg: 'Password reset successfully' });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

// Profile (unchanged)
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json({ success: true, user });
    } catch (error) {
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

app.get('/api/test', (req, res) => {
    res.json({ success: true, msg: 'Server working!', timestamp: new Date().toISOString() });
});

// Test user creation
async function createTestUser() {
    try {
        const exists = await User.findOne({ email: 'ionodecloud@gmail.com' });
        if (!exists) {
            await User.create({
                email: 'ionodecloud@gmail.com',
                password: await bcrypt.hash('password123', 12)
            });
            console.log('✅ Test user created');
        }
    } catch (error) {
        console.error('Test user error:', error);
    }
}
createTestUser();

const PORT = process.env.PORT || 5555;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
