# SQL Injection — Blind (Boolean-Based)

## Vulnerability Type
`sqli_blind` — CWE-89 — OWASP A03:2021 Injection

## Architecture
- **Backend**: Node.js Express OR Python Flask
- **Database**: SQLite (embedded)
- **Container**: Single container

## Vulnerable Code Pattern (MUST USE)

### Node.js (Preferred)
```javascript
// VULNERABLE: sqli_blind — raw string interpolation, different responses for true/false
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    try {
        const user = db.prepare(query).get();
        if (user) return res.send("Welcome back, user!");
        return res.send("Invalid credentials.");
    } catch (e) {
        return res.send("Invalid credentials.");  // Hide SQL errors
    }
});
```

### Python Flask
```python
# VULNERABLE: sqli_blind — f-string SQL, boolean oracle via different responses
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    try:
        cursor.execute(query)
        result = cursor.fetchone()
        if result:
            return "Welcome back, user!"
        return "Invalid credentials."
    except:
        return "Invalid credentials."
```

## Secure Code Pattern (MUST AVOID)
```javascript
// SAFE — parameterized (DO NOT USE)
const stmt = db.prepare("SELECT * FROM users WHERE username = ? AND password = ?");
```

## Database Schema
```sql
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
CREATE TABLE secrets (id INTEGER PRIMARY KEY, flag TEXT);
INSERT INTO users VALUES (1, 'admin', 'SuperSecretPass2024!');
INSERT INTO secrets VALUES (1, 'FLAG_PLACEHOLDER');
```

## Flag Delivery
- Flag in `secrets` table — NOT directly visible
- Player must extract character-by-character using boolean conditions
- Different response text for true vs false ("Welcome" vs "Invalid")

## Exploit Payload
```
username: admin' AND SUBSTR((SELECT flag FROM secrets LIMIT 1),1,1)='C'--
password: anything
```
Player scripts a loop cycling through each character position and character value.

## Validation Criteria
- Login endpoint returns DIFFERENT text for valid vs invalid queries
- NO error messages leaked (blind, not error-based)
- Flag table exists but flag is never shown directly
- Boolean extraction payload must work
