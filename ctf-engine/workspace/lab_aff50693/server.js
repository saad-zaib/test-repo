const express = require('express');
const betterSqlite3 = require('better-sqlite3');
const app = express();
const db = betterSqlite3('database.db');

// Initialize database
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    password TEXT
  );
  CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY,
    flag TEXT
  );
  INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'SuperSecretPass2024!');
  INSERT OR IGNORE INTO secrets (flag) VALUES ('CTF{test}');
`);

app.use(express.json());

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    const user = db.prepare(query).get();
    
    if (user) return res.send("Welcome! " + (user.flag || user.username || JSON.stringify(user)));
    return res.status(401).send("Invalid credentials");
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});