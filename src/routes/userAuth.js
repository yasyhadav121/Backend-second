const express = require('express');

const authRouter = express.Router();
const {
    register, 
    login, 
    logout, 
    adminRegister, 
    deleteProfile, 
    verify
} = require('../controllers/userAuthent');
const userMiddleware = require("../middleware/userMiddleware");
const adminMiddleware = require('../middleware/adminMiddleware');

// ============================================
// PUBLIC ROUTES (No authentication required)
// ============================================

// User registration
authRouter.post('/register', register);

// User login
authRouter.post('/login', login);

// ============================================
// PROTECTED ROUTES (Authentication required)
// ============================================

// Verify token / Check authentication status
// Use this to restore user on page refresh
authRouter.get('/check', userMiddleware, (req, res) => {
    const reply = {
        firstName: req.result.firstName,
        emailId: req.result.emailId,
        _id: req.result._id,
        role: req.result.role,
    };

    res.status(200).json({
        success: true,
        user: reply,
        message: "Valid User"
    });
});

// Alternative verify endpoint using controller
authRouter.get('/verify', userMiddleware, verify);

// Logout user
authRouter.post('/logout', userMiddleware, logout);

// Delete user profile
authRouter.delete('/deleteProfile', userMiddleware, deleteProfile);

// ============================================
// ADMIN ROUTES (Admin authentication required)
// ============================================

// Register new user by admin
authRouter.post('/admin/register', adminMiddleware, adminRegister);

module.exports = authRouter;