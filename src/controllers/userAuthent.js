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

        // Generate token
        const token = jwt.sign(
            { _id: user._id, emailId: user.emailId, role: 'user' },
            process.env.JWT_KEY,
            { expiresIn: '1h' }
        );

        // Prepare response
        const reply = {
            firstName: user.firstName,
            emailId: user.emailId,
            _id: user._id,
            role: user.role,
        };

        // Set cookie with proper options
        res.cookie('token', token, {
            maxAge: 60 * 60 * 1000,
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });

        res.status(201).json({
            user: reply,
            token, // Send token in response too for localStorage
            message: "Registration Successful"
        });
    } catch (err) {
        console.error('Register Error:', err);
        
        if (err.name === 'ValidationError') {
            return res.status(400).json({ 
                message: err.message 
            });
        }
        
        if (err.code === 11000) {
            return res.status(400).json({ 
                message: "Email already exists" 
            });
        }

        res.status(400).json({ 
            message: err.message || "Registration failed" 
        });
    }
};

const login = async (req, res) => {
    try {
        const { emailId, password } = req.body;

        if (!emailId) {
            return res.status(400).json({ 
                message: "Email is required" 
            });
        }
        if (!password) {
            return res.status(400).json({ 
                message: "Password is required" 
            });
        }

        // Find user
        const user = await User.findOne({ emailId });
        if (!user) {
            return res.status(401).json({ 
                message: "Invalid credentials" 
            });
        }

        // Compare password
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ 
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

        // Generate token
        const token = jwt.sign(
            { _id: user._id, emailId: user.emailId, role: user.role },
            process.env.JWT_KEY,
            { expiresIn: '1h' }
        );

        // Set cookie
        res.cookie('token', token, {
            maxAge: 60 * 60 * 1000,
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });

        res.status(200).json({
            user: reply,
            token, // Send token in response too for localStorage
            message: "Login Successful"
        });
    } catch (err) {
        console.error('Login Error:', err);
        res.status(500).json({ 
            message: "Login failed. Please try again" 
        });
    }
};

// NEW: Verify token endpoint
const verify = async (req, res) => {
    try {
        // Token already verified by middleware (authMiddleware)
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
        const { token } = req.cookies;

        if (!token) {
            return res.status(400).json({ 
                message: "No token found" 
            });
        }

        // Decode token
        const payload = jwt.decode(token);

        // Add to Redis blocklist
        if (redisClient && payload) {
            await redisClient.set(`token:${token}`, 'Blocked');
            await redisClient.expireAt(`token:${token}`, payload.exp);
        }

        // Clear cookie
        res.cookie("token", "", {
            expires: new Date(0),
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });

        res.status(200).json({ 
            message: "Logged out successfully" 
        });
    } catch (err) {
        console.error('Logout Error:', err);
        
        res.cookie("token", "", {
            expires: new Date(0),
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });

        res.status(200).json({ 
            message: "Logged out successfully" 
        });
    }
};

const adminRegister = async (req, res) => {
    try {
        if (req.result && req.result.role !== 'admin') {
            return res.status(403).json({ 
                message: "Access denied. Admin only" 
            });
        }

        validate(req.body);
        const { firstName, emailId, password, role } = req.body;

        const existingUser = await User.findOne({ emailId });
        if (existingUser) {
            return res.status(400).json({ 
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
            { expiresIn: '1h' }
        );

        res.cookie('token', token, {
            maxAge: 60 * 60 * 1000,
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });

        res.status(201).json({ 
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
                message: "User not found" 
            });
        }

        await Submission.deleteMany({ userId });

        res.cookie("token", "", {
            expires: new Date(0),
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });

        res.status(200).json({ 
            message: "Profile deleted successfully" 
        });
    } catch (err) {
        console.error('Delete Profile Error:', err);
        res.status(500).json({ 
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
    verify // Export new function
};