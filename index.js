require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const routes = require('./routes'); 
const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// Load Routes
app.use('/api', routes);

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected successfully'))
  .catch((err) => console.log('MongoDB connection error:', err));

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
