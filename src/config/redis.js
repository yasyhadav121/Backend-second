// config/redis.js
const { createClient } = require('redis');
require('dotenv').config();

const redisClient = createClient({
    username: process.env.REDIS_USERNAME || 'default',
    password: process.env.REDIS_PASSWORD,
    socket: {
        host: process.env.REDIS_HOST,
        port: parseInt(process.env.REDIS_PORT)
    }
});

// Error handling
redisClient.on('error', (err) => {
    console.error('Redis Client Error:', err);
});

redisClient.on('connect', () => {
    console.log('✅ Redis Connected Successfully');
});

// IMPORTANT: Don't connect here, connect in server.js
// Remove the auto-connect IIFE

module.exports = redisClient;