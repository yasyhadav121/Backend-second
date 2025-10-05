const mongoose = require('mongoose');

// Cached connection for serverless
let cachedConnection = null;

const main = async () => {
  // Return cached connection if it exists and is ready
  if (cachedConnection && mongoose.connection.readyState === 1) {
    console.log('Using cached MongoDB connection');
    return cachedConnection;
  }

  try {
    // Configure mongoose for serverless
    mongoose.set('strictQuery', false);
    
    const connection = await mongoose.connect(process.env.DB_CONNECT_STRING, {
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10, // Limit connection pool for serverless
      minPoolSize: 2,
      maxIdleTimeMS: 10000,
      // Important for serverless environments
      bufferCommands: false,
      autoIndex: true
    });

    cachedConnection = connection;
    console.log('✅ MongoDB Connected');
    return connection;
    
  } catch (err) {
    console.error('❌ MongoDB Connection Error:', err);
    cachedConnection = null;
    throw err;
  }
};

// Handle connection events
mongoose.connection.on('error', (err) => {
  console.error('MongoDB Error:', err);
  cachedConnection = null;
});

mongoose.connection.on('disconnected', () => {
  console.log('MongoDB Disconnected');
  cachedConnection = null;
});

module.exports = main;