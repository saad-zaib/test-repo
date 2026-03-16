const express = require("express");
const app = express();
const db = require("better-sqlite3")("./database.db");

app.use(express.json());

// Create tables and seed data
const initDB = () => {
  db.prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)").run();
  db.prepare("CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY, flag TEXT)").run();
  db.prepare("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)").run("admin", "SuperSecretPass2024!");
  db.prepare("INSERT OR IGNORE INTO secrets (flag) VALUES (?)").run("CTF{test}");
};

initDB();

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username =  AND password = `;
  const user = db.prepare(query).get();
  if (user) return res.send(`Welcome! ${user.flag || user.username}`);
  return res.status(401).send("Invalid credentials");
});

app.listen(3000, () => console.log("Server running on port 3000"));
