const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const cors = require('cors');

const userRoutes = require('./Routes/userRoutes');

const app = express();

// Hardcoded configuration values
const MONGODB_URI = 'mongodb://127.0.0.1:27017/eventManager';  // Replace with your MongoDB URI
const CORS_ORIGIN = '*';  // Replace with your allowed origin if needed
const PORT = 3000;  // Set your port number

// Middleware
app.use(bodyParser.json()); // Parse JSON bodies
app.use(cookieParser()); // Parse cookies
app.use(helmet()); // Adds security headers
app.use(cors({
  origin: CORS_ORIGIN, // Dynamically load origin from hardcoded value
  credentials: true // Allow cookies to be sent along with requests
}));

// Connect to MongoDB with more robust error handling
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1); // Exit the process if the database connection fails
  });

// Routes
app.use('/', userRoutes);

// Global error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 Not Found handler (for undefined routes)
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
