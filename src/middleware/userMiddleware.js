const jwt = require("jsonwebtoken");
const User = require("../models/user");
const redisClient = require("../config/redis");

const userMiddleware = async (req, res, next) => {
    try {
        // Check both cookies and Authorization header
        let token = req.cookies?.token;
        
        // If no cookie, check Authorization header
        if (!token) {
            const authHeader = req.headers.authorization;
            if (authHeader && authHeader.startsWith('Bearer ')) {
                token = authHeader.substring(7);
            }
        }

        if (!token) {
            return res.status(401).json({ 
                success: false,
                message: "Token is not present" 
            });
        }

        // Verify JWT token
        const payload = jwt.verify(token, process.env.JWT_KEY);
        const { _id } = payload;

        if (!_id) {
            return res.status(401).json({ 
                success: false,
                message: "Invalid token" 
            });
        }

        // Find user in database
        const result = await User.findById(_id);

        if (!result) {
            return res.status(401).json({ 
                success: false,
                message: "User doesn't exist" 
            });
        }

        // Check if token is blocked in Redis
        const isBlocked = await redisClient.exists(`token:${token}`);

        if (isBlocked) {
            return res.status(401).json({ 
                success: false,
                message: "Token has been invalidated" 
            });
        }

        req.result = result;
        req.token = token; // Store token for later use

        next();
    } catch (err) {
        console.error("Auth Middleware Error:", err);
        
        if (err.name === 'JsonWebTokenError') {
            return res.status(401).json({ 
                success: false,
                message: "Invalid token" 
            });
        }
        
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                success: false,
                message: "Token has expired" 
            });
        }

        res.status(401).json({ 
            success: false,
            message: "Authentication failed: " + err.message 
        });
    }
};

module.exports = userMiddleware;