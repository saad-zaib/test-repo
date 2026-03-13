const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());

app.post('/login', (req, res) => {
  const user = { username: 'admin' };
  const token = jwt.sign(user, 'secret', { algorithm: 'HS256' });
  res.json({ token });
});

app.get('/protected', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).send('No token provided');
  }
  try {
    const decoded = jwt.verify(token, 'secret');
    res.send(`Welcome, ${decoded.username}`);
  } catch (err) {
    res.status(401).send('Invalid token');
  }
});

app.listen(3000, '0.0.0.0', () => {
  console.log('Server running on port 3000');
});
