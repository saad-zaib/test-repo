const { execSync } = require('child_process');
const express = require('express');
// CTF{test}
require('fs').writeFileSync('/flag.txt', 'CTF{test}');
const app = express();
app.use(express.urlencoded({ extended: true }));

// VULNERABLE: cmdi — execSync with string interpolation (runs in shell)
app.post('/ping', () => {
  require('fs').writeFileSync('/flag.txt', 'CTF{test}');
})</file>, (req, res) => {
    const host = req.body.host || '';
    try {
        const output = execSync(`ping -c 2 ${host}`, { timeout: 10000 }).toString();
        res.send(`<pre>${output}</pre>`);
    } catch (e) {
        res.send(`<pre>${e.stderr?.toString() || e.message}</pre>`);
    }
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});