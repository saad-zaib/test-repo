# SQL Injection — UNION-Based

## Vulnerability Type
`sqli_union` — CWE-89 — OWASP A03:2021 Injection

## Architecture
- **Backend**: Node.js Express OR Python Flask
- **Database**: SQLite (via `better-sqlite3` for Node or `sqlite3` for Python)
- **Container**: Single container with embedded SQLite

## Vulnerable Code Pattern (MUST USE)

### Node.js (Preferred)
```javascript
// VULNERABLE: sqli_union — raw string interpolation
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    const user = db.prepare(query).get();
    if (user) return res.send("Welcome! " + user.flag);
    return res.status(401).send("Invalid credentials");
});
```

### Python Flask
```python
# VULNERABLE: sqli_union — f-string SQL construction
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)  # NO parameter tuple
    result = cursor.fetchone()
```

## Secure Code Pattern (MUST AVOID — these fix the vulnerability)
```javascript
// SAFE — parameterized query (DO NOT USE)
const stmt = db.prepare("SELECT * FROM users WHERE username = ? AND password = ?");
const user = stmt.get(username, password);
```
```python
# SAFE — parameterized query (DO NOT USE)
cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
```

## Database Schema
```sql
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
CREATE TABLE secrets (id INTEGER PRIMARY KEY, flag TEXT);
INSERT INTO users VALUES (1, 'admin', 'SuperSecretPass2024!');
INSERT INTO secrets VALUES (1, 'FLAG_PLACEHOLDER');
```
Replace `FLAG_PLACEHOLDER` with the actual flag value.

## Flag Delivery
- Flag lives in the `secrets` table, column `flag`
- Successful UNION injection retrieves it
- Flag displayed in the HTTP response body after injection

## Exploit Payload
```
username: ' UNION SELECT flag,null FROM secrets--
password: anything
```
POST to `/login` with form data.

## Docker Setup
```yaml
services:
  app:
    build: .
    ports:
      - "3000:3000"
```

## Validation Criteria
- The SQL query MUST use string concatenation or template literals with user input
- No parameterized queries (?, %s, $1) at the injection point
- No ORM (SQLAlchemy, Sequelize, Mongoose) — raw SQL only
- The `secrets` table MUST exist with the flag value
- UNION SELECT must return the flag in the response body
