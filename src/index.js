const express = require('express');
const app = express();
require('dotenv').config();
const main = require('./config/db');
const cookieParser = require('cookie-parser');
const authRouter = require("./routes/userAuth");
const redisClient = require('./config/redis');
const problemRouter = require("./routes/problemCreator");
const submitRouter = require("./routes/submit");
const aiRouter = require("./routes/aiChatting");
const videoRouter = require("./routes/videoCreator");
const cors = require('cors');

// CORS Configuration
app.use(cors({
  origin: 'http://localhost:5173',
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

// Initialize Connections
const initializeConnection = async () => {
  try {
    // Check if Redis is already connected
    if (!redisClient.isOpen) {
      await Promise.all([
        main(), 
        redisClient.connect()
      ]);
      console.log('✅ MongoDB & Redis Connected');
    } else {
      await main();
      console.log('✅ MongoDB Connected (Redis already connected)');
    }
    
    // Start Server
    const server = app.listen(process.env.PORT || 5000, () => {
      console.log(`🚀 Server listening on port ${process.env.PORT || 5000}`);
    });

    // Graceful Shutdown
    const gracefulShutdown = async (signal) => {
      console.log(`\n${signal} received. Closing gracefully...`);
      
      server.close(async () => {
        console.log('HTTP server closed');
        
        try {
          if (redisClient.isOpen) {
            await redisClient.quit();
            console.log('Redis connection closed');
          }
          console.log('✅ Graceful shutdown completed');
          process.exit(0);
        } catch (err) {
          console.error('Error during shutdown:', err);
          process.exit(1);
        }
      });

      // Force close after 10 seconds
      setTimeout(() => {
        console.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
      }, 10000);
    };

    // Handle shutdown signals
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  } catch (err) {
    console.error('❌ Initialization Error:', err);
    process.exit(1);
  }
};

// Error Handling
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

// Start Application
initializeConnection();