require('dotenv').config();
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;


process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

const cors = require('cors'); 
const express = require('express');
const mongoose = require('mongoose');
const winston = require('winston');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;

const allowedOrigins = [
  'http://localhost:5173',
  'https://frontend-repo-vert.vercel.app'
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }

  next();
});






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

// Login route


app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    logger.warn('POST /login with missing fields');
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      logger.warn(`POST /login - Email not found: ${email}`);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      logger.warn(`POST /login - Invalid password for email: ${email}`);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    //  Generate JWT Token
    const token = jwt.sign(
      { email: user.email, userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    logger.info(`User logged in: ${email}`);
    res.status(200).json({
      message: 'Login successful',
      token,
      user: { username: user.username, email: user.email }
    });
  } catch (error) {
    logger.error(`Login failed: ${error.message}`);
    res.status(500).json({ error: 'Server error' });
  }
});




// Middleware to authenticate user from JWT (if you're using tokens)
const authenticateUser = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized: No token provided" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { email: '...', userId: '...' }
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};

// Update user details (username, email, password)
app.put('/edit-user', authenticateUser, async (req, res) => {
  const { newUsername, newEmail, currentPassword, newPassword } = req.body;
  const userEmail = req.user.email;

  try {
    const user = await User.findOne({ email: userEmail });

    if (!user) {
      logger.warn(`PUT /edit-user - User not found with email: ${userEmail}`);
      return res.status(404).json({ error: 'User not found' });
    }

    // Update username
    if (newUsername) user.username = newUsername;

    // Update email (after checking it's not already taken)
    if (newEmail && newEmail !== user.email) {
      const emailExists = await User.findOne({ email: newEmail });
      if (emailExists) {
        logger.warn(`PUT /edit-user - New email already in use: ${newEmail}`);
        return res.status(409).json({ error: 'Email already in use' });
      }
      user.email = newEmail;
    }

    // Update password (requires current password)
    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ error: 'Current password required to change password' });
      }

      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
    }

    await user.save();

    logger.info(`User updated: ${userEmail}`);
    res.status(200).json({
      message: 'User updated successfully',
      user: { username: user.username, email: user.email }
    });
  } catch (error) {
    logger.error(`PUT /edit-user failed: ${error.message}`);
    res.status(500).json({ error: 'Server error' });
  }
});



// Start server
app.listen(port, () => {
  logger.info(` Server running at http://localhost:${port}`);
});
