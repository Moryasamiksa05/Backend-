const express = require('express');
const app = express();
const port = 3000;

app.use(express.json());

// GET API
app.get('/', (req, res) => {
  res.send('Welcome');
});

// POST API
app.post('/name', (req, res) => {
  const { name } = req.body;
  if (!name) {
    return res.status(400).json({ error: 'Name is required' });
  }
  res.json({ name });
});

// Start server
app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
