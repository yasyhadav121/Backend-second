const redisClient = require("../config/redis");
const User = require("../models/user");
const validate = require('../utils/validator');
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');
const Submission = require("../models/submission");

const register = async (req, res) => {
    try {
        // Validate the data
        validate(req.body);
        const { firstName, emailId, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ emailId });
        if (existingUser) {
            return res.status(400).json({ 
                success: false,
                message: "User already exists with this email" 
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user object
        const userData = {
            firstName,
            emailId,
            password: hashedPassword,
            role: 'user'
        };

        // Create user
        const user = await User.create(userData);

        // Generate token with longer expiry for better UX
        const token = jwt.sign(
            { _id: user._id, emailId: user.emailId, role: user.role },
            process.env.JWT_KEY,
            { expiresIn: '7d' } // Changed from 1h to 7d
        );

        // Prepare response
        const reply = {
            firstName: user.firstName,
            emailId: user.emailId,
            _id: user._id,
            role: user.role,
        };

        // Set cookie only for localhost/development
        // Vercel pe cookies cross-origin mein kaam nahi karti
        if (process.env.NODE_ENV !== 'production') {
            res.cookie('token', token, {
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
                httpOnly: true,
                secure: false,
                sameSite: 'lax'
            });
        }

        res.status(201).json({
            success: true,
            user: reply,
            token, // Frontend localStorage mein save karega
            message: "Registration Successful"
        });
    } catch (err) {
        console.error('Register Error:', err);
        
        if (err.name === 'ValidationError') {
            return res.status(400).json({ 
                success: false,
                message: err.message 
            });
        }
        
        if (err.code === 11000) {
            return res.status(400).json({ 
                success: false,
                message: "Email already exists" 
            });
        }

        res.status(400).json({ 
            success: false,
            message: err.message || "Registration failed" 
        });
    }
};

const login = async (req, res) => {
    try {
        const { emailId, password } = req.body;

        if (!emailId) {
            return res.status(400).json({ 
                success: false,
                message: "Email is required" 
            });
        }
        if (!password) {
            return res.status(400).json({ 
                success: false,
                message: "Password is required" 
            });
        }

        // Find user
        const user = await User.findOne({ emailId });
        if (!user) {
            return res.status(401).json({ 
                success: false,
                message: "Invalid credentials" 
            });
        }

        // Compare password
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ 
                success: false,
                message: "Invalid credentials" 
            });
        }

        // Prepare response
        const reply = {
            firstName: user.firstName,
            emailId: user.emailId,
            _id: user._id,
            role: user.role,
        };

        // Generate token with longer expiry
        const token = jwt.sign(
            { _id: user._id, emailId: user.emailId, role: user.role },
            process.env.JWT_KEY,
            { expiresIn: '7d' } // Changed from 1h to 7d
        );

        // Set cookie only for development
        if (process.env.NODE_ENV !== 'production') {
            res.cookie('token', token, {
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
                httpOnly: true,
                secure: false,
                sameSite: 'lax'
            });
        }

        res.status(200).json({
            success: true,
            user: reply,
            token, // Frontend localStorage mein save karega
            message: "Login Successful"
        });
    } catch (err) {
        console.error('Login Error:', err);
        res.status(500).json({ 
            success: false,
            message: "Login failed. Please try again" 
        });
    }
};

// Verify token endpoint - user restore karne ke liye
const verify = async (req, res) => {
    try {
        // Token already verified by middleware (userMiddleware)
        // req.result contains the user data from middleware
        
        const user = await User.findById(req.result._id).select('-password');
        
        if (!user) {
            return res.status(404).json({ 
                success: false,
                message: "User not found" 
            });
        }

        res.status(200).json({ 
            success: true,
            user: {
                _id: user._id,
                firstName: user.firstName,
                emailId: user.emailId,
                role: user.role
            }
        });
    } catch (err) {
        console.error('Verify Error:', err);
        res.status(401).json({ 
            success: false,
            message: "Token verification failed" 
        });
    }
};

const logout = async (req, res) => {
    try {
        // Token cookie ya Authorization header se lena hai
        let token = req.cookies?.token;
        
        if (!token) {
            const authHeader = req.headers.authorization;
            if (authHeader && authHeader.startsWith('Bearer ')) {
                token = authHeader.substring(7);
            }
        }

        if (!token) {
            return res.status(400).json({ 
                success: false,
                message: "No token found" 
            });
        }

        // Decode token
        const payload = jwt.decode(token);

        // Add to Redis blocklist
        if (redisClient && payload) {
            try {
                await redisClient.set(`token:${token}`, 'Blocked');
                await redisClient.expireAt(`token:${token}`, payload.exp);
            } catch (redisErr) {
                console.error('Redis Error:', redisErr);
                // Continue with logout even if Redis fails
            }
        }

        // Clear cookie (if exists)
        res.cookie("token", "", {
            expires: new Date(0),
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });

        res.status(200).json({ 
            success: true,
            message: "Logged out successfully" 
        });
    } catch (err) {
        console.error('Logout Error:', err);
        
        // Clear cookie anyway
        res.cookie("token", "", {
            expires: new Date(0),
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });

        res.status(200).json({ 
            success: true,
            message: "Logged out successfully" 
        });
    }
};

const adminRegister = async (req, res) => {
    try {
        // Check if user is admin
        if (!req.result || req.result.role !== 'admin') {
            return res.status(403).json({ 
                success: false,
                message: "Access denied. Admin only" 
            });
        }

        validate(req.body);
        const { firstName, emailId, password, role } = req.body;

        const existingUser = await User.findOne({ emailId });
        if (existingUser) {
            return res.status(400).json({ 
                success: false,
                message: "User already exists with this email" 
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const userData = {
            firstName,
            emailId,
            password: hashedPassword,
            role: role || 'user'
        };

        const user = await User.create(userData);

        const token = jwt.sign(
            { _id: user._id, emailId: user.emailId, role: user.role },
            process.env.JWT_KEY,
            { expiresIn: '7d' }
        );

        // Set cookie only in development
        if (process.env.NODE_ENV !== 'production') {
            res.cookie('token', token, {
                maxAge: 7 * 24 * 60 * 60 * 1000,
                httpOnly: true,
                secure: false,
                sameSite: 'lax'
            });
        }

        res.status(201).json({ 
            success: true,
            message: "User registered successfully",
            user: {
                firstName: user.firstName,
                emailId: user.emailId,
                _id: user._id,
                role: user.role
            },
            token
        });
    } catch (err) {
        console.error('Admin Register Error:', err);
        res.status(400).json({ 
            success: false,
            message: err.message || "Registration failed" 
        });
    }
};

const deleteProfile = async (req, res) => {
    try {
        const userId = req.result._id;

        const deletedUser = await User.findByIdAndDelete(userId);
        
        if (!deletedUser) {
            return res.status(404).json({ 
                success: false,
                message: "User not found" 
            });
        }

        // Delete all submissions by this user
        await Submission.deleteMany({ userId });

        // Clear cookie
        res.cookie("token", "", {
            expires: new Date(0),
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });

        res.status(200).json({ 
            success: true,
            message: "Profile deleted successfully" 
        });
    } catch (err) {
        console.error('Delete Profile Error:', err);
        res.status(500).json({ 
            success: false,
            message: "Failed to delete profile" 
        });
    }
};

module.exports = { 
    register, 
    login, 
    logout, 
    adminRegister, 
    deleteProfile,
    verify
};