const express = require('express');
const app = express();
require('dotenv').config();
const main = require('../config/db');
const cookieParser = require('cookie-parser');
const authRouter = require("../routes/userAuth");
const redisClient = require('../config/redis');
const problemRouter = require("../routes/problemCreator");
const submitRouter = require("../routes/submit");
const aiRouter = require("../routes/aiChatting");
const videoRouter = require("../routes/videoCreator");
const cors = require('cors');

// CORS Configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware
app.use(express.json());
app.use(cookieParser());

// Routes
app.use('/user', authRouter);
app.use('/problem', problemRouter);
app.use('/submission', submitRouter);
app.use('/ai', aiRouter);
app.use("/video", videoRouter);

// Health Check Route
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    message: 'Server is running',
    redis: redisClient.isOpen ? 'Connected' : 'Disconnected'
  });
});

// Root route
app.get('/', (req, res) => {
  res.json({ message: 'API is running' });
});

// Initialize connections only once (singleton pattern)
let isInitialized = false;

const initializeConnection = async () => {
  if (isInitialized) return;
  
  try {
    // Connect to MongoDB (reuse existing connections)
    await main();
    
    // Connect to Redis if not already connected
    if (!redisClient.isOpen) {
      await redisClient.connect();
    }
    
    isInitialized = true;
    console.log('✅ Connections initialized');
  } catch (err) {
    console.error('❌ Initialization Error:', err);
    throw err;
  }
};

// Middleware to initialize connections before each request
app.use(async (req, res, next) => {
  try {
    await initializeConnection();
    next();
  } catch (err) {
    res.status(500).json({ error: 'Database connection failed' });
  }
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error'
  });
});

// Export the Express app as a serverless function
module.exports = app;