require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const winston = require('winston');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;

// Body parser
app.use(express.json());

// Setup Winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} [${level.toUpperCase()}]: ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'app.log' }),
  ],
});

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => logger.info(" MongoDB Connected"))
.catch((err) => logger.error(" MongoDB Connection Error: " + err));

// Mongoose Schemas & Models
const nameSchema = new mongoose.Schema({
  name: String,
});
const NameModel = mongoose.model("Name", nameSchema);

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
const User = mongoose.model("User", userSchema);

// Routes
app.get('/', (req, res) => {
  logger.info('GET / called');
  res.send('Welcome to the MongoDB-connected backend!');
});

// Save name to MongoDB
app.post('/name', async (req, res) => {
  const { name } = req.body;

  if (!name) {
    logger.warn('POST /name with missing name');
    return res.status(400).json({ error: 'Name is required' });
  }

  try {
    const newName = new NameModel({ name });
    await newName.save();

    logger.info(`POST /name saved: ${name}`);
    res.json({ name });
  } catch (error) {
    logger.error(`Error saving name: ${error.message}`);
    res.status(500).json({ error: "Server error" });
  }
});

// Register user
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    logger.warn('POST /register with missing fields');
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      logger.warn(`POST /register - Email already exists: ${email}`);
      return res.status(409).json({ error: 'Email already registered' });
    }

    //  Hash password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    logger.info(`User registered: ${email}`);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    logger.error(`Registration failed: ${error.message}`);
    res.status(500).json({ error: 'Server error' });
  }
});

// Start server
app.listen(port, () => {
  logger.info(` Server running at http://localhost:${port}`);
});
