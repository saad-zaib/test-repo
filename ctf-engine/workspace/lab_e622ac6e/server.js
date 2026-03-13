const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());

app.post('/login', (req, res) => {
  const token = jwt.sign({ username: 'admin' }, 'secret', { algorithm: 'none' });
  res.json({ token });
});

app.get('/protected', (req, res) => {
  try {
    const decoded = jwt.verify(req.headers.authorization, 'secret');
    res.send('Access granted');
  } catch (err) {
    res.status(401).send('Unauthorized');
  }
});

app.listen(3000, '0.0.0.0', () => {
  console.log('Server running on port 3000');
});
