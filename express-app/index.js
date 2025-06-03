
const express = require('express');
const winston = require('winston');

const app = express();
const port = 3000;

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

// Routes
app.get('/', (req, res) => {
  logger.info('GET / called');
  res.send('Welcome');
});

app.post('/name', (req, res) => {
  const { name } = req.body;
  
  if (!name) {
    logger.warn('POST /name with missing name');
    return res.status(400).json({ error: 'Name is required' });
  }

  logger.info(`POST /name with name: ${name}`);
  res.json({ name });
});

// Start server
app.listen(port, () => {
  logger.info(`Server running at http://localhost:${port}`);
});
