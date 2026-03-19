const express = require('express');
const betterSqlite3 = require('better-sqlite3');
const app = express();
app.use(express.json());

const db = new betterSqlite3('db.sqlite');

// Create tables and seed data
const initDb = () => {
  db.prepare('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)').run();
  db.prepare('CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY, flag TEXT)').run();
  
  // Seed admin user
  db.prepare('INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)')
    .run('admin', 'SuperSecretPass2024!');
  
  // Embed flag in secrets table
  db.prepare('INSERT OR IGNORE INTO secrets (flag) VALUES (?)')
    .run('CTF{test}');
};

initDb();

// VULNERABLE: sqli_union — raw string interpolation
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    const user = db.prepare(query).get();
    
    // Check if we got a user back, and print properties that might contain the flag
    if (user) return res.send("Welcome! " + (user.flag || user.username || JSON.stringify(user)));
    return res.status(401).send("Invalid credentials");
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});