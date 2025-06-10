require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const winston = require('winston');

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
.then(() => logger.info("MongoDB Connected"))
.catch((err) => logger.error("MongoDB Connection Error: " + err));

// Mongoose Schema & Model
const nameSchema = new mongoose.Schema({
  name: String,
});

const NameModel = mongoose.model("Name", nameSchema);

// Routes
app.get('/', (req, res) => {
  logger.info('GET / called');
  res.send('Welcome to the MongoDB-connected backend!');
});

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

// Start server
app.listen(port, () => {
  logger.info(`Server running at http://localhost:${port}`);
});
