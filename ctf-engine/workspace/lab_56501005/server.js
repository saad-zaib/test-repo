const express = require('express');
const betterSqlite3 = require('better-sqlite3');
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const db = new betterSqlite3('app.db');
db.pragma('foreign_keys = ON');

// Create tables and seed data
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
`);

// Seed users table
db.prepare("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)")
  .run('admin', 'SuperSecretPass2024!');

// Seed secrets table with the flag
db.prepare("INSERT OR IGNORE INTO secrets (flag) VALUES (?)")
  .run('CTF{test}');

// VULNERABLE: sqli_union — raw string interpolation
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    const user = db.prepare(query).get();
    
    if (user) return res.send("Welcome! " + (user.flag || user.username || JSON.stringify(user)));
    return res.status(401).send("Invalid credentials");
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});