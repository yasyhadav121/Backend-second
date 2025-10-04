const express = require('express');

const authRouter = express.Router();
const {register, login, logout, adminRegister, deleteProfile, verify} = require('../controllers/userAuthent')
const userMiddleware = require("../middleware/userMiddleware");
const adminMiddleware = require('../middleware/adminMiddleware');

// Register & Login
authRouter.post('/register', register);
authRouter.post('/login', login);
authRouter.post('/logout', userMiddleware, logout);
authRouter.post('/admin/register', adminMiddleware, adminRegister);
authRouter.delete('/deleteProfile', userMiddleware, deleteProfile);

// Token verification (you already have /check doing this!)
authRouter.get('/check', userMiddleware, (req, res) => {
    const reply = {
        firstName: req.result.firstName,
        emailId: req.result.emailId,
        _id: req.result._id,
        role: req.result.role,
    }

    res.status(200).json({
        success: true, // Add this for consistency
        user: reply,
        message: "Valid User"
    });
});

// Alternative: if you want to use the verify controller function
// authRouter.get('/verify', userMiddleware, verify);

module.exports = authRouter;