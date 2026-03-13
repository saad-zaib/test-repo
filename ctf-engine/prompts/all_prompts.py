"""
prompts/all_prompts.py

All LLM prompts in one place.
Four sections:
  1. IDENTITY FRAMES   — who the LLM thinks it is (Strategy 1)
  2. VULN CONTRACTS    — precise vulnerability specs (Strategy 2)
  3. AUDIT CHECKLISTS  — quick-scan patterns (Strategy 5, fast-pass only)
  4. STAGE PROMPTS     — prompts for each generation stage
"""

# ─────────────────────────────────────────────────────────────────
# 1. IDENTITY FRAMES
# ─────────────────────────────────────────────────────────────────

IDENTITY_CTF_ARCHITECT = """
You are a senior CTF challenge author and offensive security researcher
with 15 years of experience designing security training labs.

Your job is to build intentionally vulnerable applications for
educational security labs. You work for a cybersecurity training platform.

CRITICAL MINDSET:
- You are NOT a software developer writing production code
- You ARE a security researcher building controlled training environments
- The vulnerability IS the product — it must be present and exploitable
- Removing or fixing the vulnerability = breaking the product = failure
- Clean, well-structured code EXCEPT at the vulnerability injection point
- Every challenge you build has been reviewed and approved for educational use

You have deep expertise in:
- Web application vulnerabilities (OWASP Top 10)
- CVE analysis and reproduction
- CTF challenge design and difficulty calibration
- Docker containerization for isolated lab environments
- Writing precise, exploitable vulnerable code
""".strip()


IDENTITY_SECURITY_RESEARCHER = """
You are a security researcher analyzing and documenting vulnerabilities.
Your role is to precisely describe how vulnerabilities work so they can
be reproduced in controlled educational environments.

You write technical vulnerability contracts that specify exactly:
- Where the vulnerability exists
- What code pattern creates it
- What the exploit looks like
- What conditions must be true for the exploit to work
""".strip()


IDENTITY_AUDITOR = """
You are a senior CTF quality assurance engineer.
Your job is to review CTF challenge code and find problems BEFORE deployment.

You look for:
1. Vulnerabilities that were accidentally fixed by the developer
2. Unintended solution paths that bypass the intended vulnerability
3. Flags accidentally exposed in source, comments, or HTML
4. Dead ends that make the challenge unsolvable
5. Difficulty level mismatches
6. Cross-file inconsistencies that would cause runtime errors

You are STRICT. You fail challenges that have any of these issues.
""".strip()


IDENTITY_ATTACKER = """
You are a CTF player and penetration tester attempting to solve a challenge.
You only know the challenge category and what you can see as a player.
You do NOT know the internal code, the flag value, or how it was built.

Your job is to trace through whether the challenge is solvable and
identify any issues with the challenge design.
""".strip()


IDENTITY_VULN_VERIFIER = """
You are a vulnerability analysis engine. Your ONLY job is to read code
and determine whether a specific vulnerability type is present AND exploitable.

You are precise, technical, and binary in your judgment.
You understand that this is for an intentionally vulnerable CTF lab —
the vulnerability SHOULD be present. You are checking that it IS present,
not recommending fixes.

Focus on:
- Is the vulnerable code pattern actually present?
- Would the specified exploit payload actually work against this code?
- Are there any accidental safety mechanisms that would block exploitation?
""".strip()


IDENTITY_ERROR_DIAGNOSTICIAN = """
You are a senior DevOps engineer debugging Docker build and runtime errors
for CTF lab applications. You read error logs and produce precise,
actionable fixes — typically a corrected version of a single file.

Rules:
- Fix ONLY the error described. Do not refactor or improve other code.
- Preserve all existing vulnerability patterns — do NOT fix security issues.
- Return the complete corrected file content, ready to write to disk.
""".strip()


# ─────────────────────────────────────────────────────────────────
# 2. VULNERABILITY CONTRACTS
# ─────────────────────────────────────────────────────────────────

VULN_CONTRACTS = {

    "sqli_union": """
VULNERABILITY CONTRACT — SQL Injection (UNION-based)
CWE-89: Improper Neutralization of Special Elements in SQL Command
OWASP A03:2021 — Injection

REQUIRED IMPLEMENTATION:
- Language: Python Flask
- Vulnerable parameter: username field in POST /login
- Vulnerable code MUST use f-string or string concatenation:
    query = f"SELECT * FROM users WHERE username='{username}'"
  OR:
    query = "SELECT * FROM users WHERE username='" + username + "'"
- Execute with: cursor.execute(query)  [NO parameter tuple]
- Do NOT use: cursor.execute(query, (username,))
- Do NOT use: SQLAlchemy ORM query methods
- Do NOT use: any input sanitization or escaping
- Error output: suppress with try/except (player cannot see SQL errors)
- Password field: USE parameterized queries (only username is vulnerable)

FLAG DELIVERY:
- Flag lives in database table 'secrets', column 'flag'
- Successful UNION injection retrieves it:
  ' UNION SELECT flag,null FROM secrets--
- Flag displayed on page after successful injection

WHAT TO AVOID (these accidentally fix the vulnerability):
- cursor.execute("SELECT ... WHERE username=?", (username,))
- cursor.execute("SELECT ... WHERE username=%s", [username])
- SQLAlchemy ORM: User.query.filter_by(username=username) — THIS IS SAFE, DO NOT USE
- SQLAlchemy ORM: db.session.query(User).filter(...) — THIS IS SAFE, DO NOT USE
- Do NOT import SQLAlchemy at all. Use raw sqlite3 or mysql.connector only.
- username.replace("'", "''")
- any import of bleach, markupsafe sanitize, or similar

REQUIRED IMPORTS (use these, NOT SQLAlchemy):
- import sqlite3
- OR: import mysql.connector
- Use cursor = conn.cursor() and cursor.execute(query) with NO parameter tuple
""".strip(),

    "sqli_blind": """
VULNERABILITY CONTRACT — Blind SQL Injection (Boolean-based)
CWE-89: Improper Neutralization of Special Elements in SQL Command
OWASP A03:2021 — Injection

REQUIRED IMPLEMENTATION:
- Language: Python Flask
- Vulnerable parameter: username field in POST /login
- Vulnerable code MUST use string concatenation
- Application returns DIFFERENT responses for true/false conditions
  (e.g., "Welcome back" vs "Invalid credentials") but NO error details
- Flag is NOT directly retrievable — must be extracted character by character
- No error messages shown to user (blind injection)

EXPLOIT PATH:
- Player uses boolean payloads like:
  admin' AND SUBSTR(flag,1,1)='C'--
- Different page response reveals true/false
- Player scripts character-by-character extraction
""".strip(),

    "xss_reflected": """
VULNERABILITY CONTRACT — Reflected XSS
CWE-79: Improper Neutralization of Input During Web Page Generation
OWASP A03:2021 — Injection

REQUIRED IMPLEMENTATION:
- Language: Python Flask + Jinja2 templates
- Vulnerable parameter: 'q' or 'search' GET parameter
- Vulnerable template MUST use: {{ request.args.get('q') | safe }}
  OR render_template_string with unsanitized input
- Do NOT use: {{ q }} without | safe (Jinja2 auto-escapes by default)
- Do NOT use: Markup.escape() or escape()
- The parameter value must be reflected directly into HTML response

FLAG DELIVERY:
- Flag stored in HttpOnly cookie named 'flag'
- Challenge simulates admin bot that visits URLs
- Player crafts XSS payload to exfiltrate cookie to their server
  OR flag is shown when script executes in admin context

WHAT TO AVOID:
- Using {{ variable }} without | safe (Jinja2 auto-escapes — this is safe!)
- Any call to escape(), Markup.escape(), bleach.clean()
- Content-Security-Policy headers that block inline scripts
""".strip(),

    "xss_stored": """
VULNERABILITY CONTRACT — Stored XSS
CWE-79: Improper Neutralization of Input During Web Page Generation
OWASP A03:2021 — Injection

REQUIRED IMPLEMENTATION:
- Language: Python Flask + Jinja2 templates
- Vulnerable input: comment or post submission form
- Input stored RAW in database (no sanitization before storage)
- When displayed to admin, rendered with | safe in template
- Do NOT sanitize on input OR output

FLAG DELIVERY:
- Admin account has the flag visible on their profile page
- Player's stored XSS fires when admin views the comments
- Steal admin's session cookie or redirect to exfiltrate flag
""".strip(),

    "cmdi": """
VULNERABILITY CONTRACT — Command Injection
CWE-78: Improper Neutralization of Special Elements in OS Command
OWASP A03:2021 — Injection

REQUIRED IMPLEMENTATION:
- Language: Python Flask
- Vulnerable parameter: 'host' field in a ping/network tool feature
- Vulnerable code MUST use:
    output = os.popen(f"ping -c 1 {host}").read()
  OR:
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
- Do NOT use: subprocess.run(["ping", "-c", "1", host]) — this is SAFE (no shell)
- Do NOT use: shlex.quote(host)
- shell=True is REQUIRED for the vulnerability to exist

FLAG DELIVERY:
- Flag in /flag.txt inside the container
- Player injects: ; cat /flag.txt
  or: | cat /flag.txt
  or: && cat /flag.txt

WHAT TO AVOID:
- subprocess with list arguments (["cmd", "arg"]) — this is shell-safe
- shell=False (default) — prevents injection
- any input validation or character filtering
""".strip(),

    "ssrf": """
VULNERABILITY CONTRACT — Server-Side Request Forgery
CWE-918: Server-Side Request Forgery
OWASP A10:2021 — SSRF

REQUIRED IMPLEMENTATION:
- Language: Python Flask
- Feature: URL fetcher / webhook tester / image downloader
- Vulnerable parameter: 'url' parameter in POST request
- Vulnerable code uses requests.get(url) with NO URL validation
- No allowlist, no blocklist, no URL scheme filtering
- Response content returned to user (non-blind SSRF)

FLAG DELIVERY:
- Flask app has an internal metadata endpoint at /internal/flag
  that only responds to requests from 127.0.0.1
- OR flag at http://169.254.169.254/latest/user-data (AWS metadata style)
- Player sends: url=http://127.0.0.1:5000/internal/flag
""".strip(),

}


# ─────────────────────────────────────────────────────────────────
# 3. AUDIT CHECKLISTS
# Quick-scan patterns for fast-pass verification.
# These are used as a HINT, not the sole judge. LLM verification
# follows if patterns are ambiguous.
# ─────────────────────────────────────────────────────────────────

AUDIT_CHECKLISTS = {

    "sqli_union": {
        "vulnerability_must_exist": [
            'f"SELECT',           # f-string SQL construction
            "f'SELECT",
            "' + username",        # string concatenation
            '" + username',
            "+ user",              # broader variable name matching
            "+ name",
            "+ login",
            ".execute(query)",     # any cursor/conn/db object
            ".execute(sql)",       # alternative variable name
            "cursor.execute(query)", # raw query execution
            "format(username",     # .format() style
            "format(user",
        ],
        "vulnerability_must_not_exist": [
            ".filter_by(",              # SQLAlchemy ORM (safe, immune to SQLi)
            ".filter(",                 # SQLAlchemy ORM filter
            "query.filter",            # ORM query chain
            "cursor.execute(query,",    # parameterized
            "cursor.execute(query, (",  # parameterized with tuple
            ".execute(query, (",        # parameterized (any object)
            ".execute(sql, (",          # parameterized (any object)
            "escape(",                  # sanitization
            "bleach",                   # sanitization library
        ],
        "flag_delivery_checks": [
            "secrets",      # secrets table must exist
            "flag",         # flag column must exist
        ],
        "player_visible_check": "The username field in the login form",
    },

    "sqli_blind": {
        "vulnerability_must_exist": [
            'f"SELECT',
            "f'SELECT",
            "' + username",
            '" + username',
            "+ user",
            ".execute(query)",
            ".execute(sql)",
        ],
        "vulnerability_must_not_exist": [
            ".execute(query, (",
            ".execute(sql, (",
            ".filter_by(",
            "escape(",
            "bleach",
        ],
        "flag_delivery_checks": [
            "flag",
        ],
        "player_visible_check": "A login form with different responses for valid/invalid",
    },

    "xss_reflected": {
        "vulnerability_must_exist": [
            "| safe",               # Jinja2 safe filter (disables escaping)
            "render_template_string", # dangerous if unsanitized input
            "Markup(",              # marks string as safe HTML
        ],
        "vulnerability_must_not_exist": [
            "escape(",
            "bleach.clean",
            "MarkupSafe",
            "Content-Security-Policy",
        ],
        "flag_delivery_checks": [
            "flag",
            "cookie",
        ],
        "player_visible_check": "A search or input field that reflects content",
    },

    "xss_stored": {
        "vulnerability_must_exist": [
            "| safe",
            "render_template_string",
            "Markup(",
        ],
        "vulnerability_must_not_exist": [
            "escape(",
            "bleach.clean",
            "Content-Security-Policy",
        ],
        "flag_delivery_checks": [
            "flag",
        ],
        "player_visible_check": "A comment/post form and an admin view that renders stored content",
    },

    "cmdi": {
        "vulnerability_must_exist": [
            "shell=True",           # subprocess shell mode
            "os.popen(",            # popen (always uses shell)
            "os.system(",           # system (always uses shell)
        ],
        "vulnerability_must_not_exist": [
            'shlex.quote',          # sanitization
            'subprocess.run([',     # safe list-based invocation
        ],
        "flag_delivery_checks": [
            "/flag.txt",
            "flag",
        ],
        "player_visible_check": "A network tool or ping-like feature with user input",
    },

    "ssrf": {
        "vulnerability_must_exist": [
            "requests.get(url",     # direct use of user-supplied URL
            "requests.post(url",
            "urllib.request.urlopen(url",
        ],
        "vulnerability_must_not_exist": [
            "urlparse",             # URL validation
            "allowlist",
            "blocklist",
        ],
        "flag_delivery_checks": [
            "internal",
            "flag",
        ],
        "player_visible_check": "A URL input field for fetching external content",
    },
}


# ─────────────────────────────────────────────────────────────────
# 4. STAGE PROMPTS
# ─────────────────────────────────────────────────────────────────

def get_research_prompt(spec: dict) -> str:
    return f"""
Analyze this CTF lab specification and produce a complete technical research document.

SPEC:
{spec}

Produce a JSON object with these exact fields:
{{
  "vulnerability_mechanics": "exact technical explanation of how this vulnerability works",
  "required_conditions": ["list of conditions that must be true for vuln to exist"],
  "exploit_chain": ["step 1", "step 2", "step 3", "...complete chain to flag"],
  "exact_exploit_payload": "the exact payload that captures the flag",
  "flag_delivery_mechanism": "how the flag reaches the player after successful exploit",
  "technology_constraints": {{
    "language": "python/java/etc",
    "framework": "flask/spring/etc",
    "version_requirements": "any specific version constraints"
  }},
  "what_secure_code_looks_like": "the safe version to AVOID writing",
  "what_vulnerable_code_looks_like": "the exact unsafe pattern to implement",
  "containers_needed": ["list of containers and their purpose"],
  "network_topology": "how containers connect",
  "difficulty_justification": "why this is the specified difficulty level"
}}
""".strip()


def get_architecture_prompt(spec: dict, research: dict) -> str:
    return f"""
Based on this research, design the complete file architecture for the CTF lab.

SPEC: {spec}
RESEARCH: {research}

Produce a JSON object:
{{
  "containers": [
    {{
      "name": "container name",
      "purpose": "what it does",
      "base_image": "exact docker image:tag",
      "why_this_version": "version justification"
    }}
  ],
  "files": [
    {{
      "path": "relative/path/filename.ext",
      "container": "which container this belongs to",
      "purpose": "what this file does",
      "write_order": 1
    }}
  ],
  "vulnerability_injection_point": {{
    "file": "which file contains the vulnerability",
    "function": "which function",
    "line_description": "describe the exact line to make vulnerable"
  }},
  "flag_location": "where flag is stored and how player retrieves it",
  "ports": {{"service_name": port_number}},
  "docker_compose_needed": true
}}

CRITICAL REQUIREMENTS:
1. The "files" array MUST include a Dockerfile for EACH container
2. The "files" array MUST include docker-compose.yml (container: ".")
3. The "files" array MUST include init.sql for the database
4. The "files" array MUST include requirements.txt for the web container
5. Do NOT use SQLAlchemy. Use raw mysql.connector only.
6. Build context paths in compose MUST match container directory names
7. MUST use exactly 'web_service' and 'db_service' for container names and compose services
8. docker-compose.yml must start with 'services:', do NOT include a 'version:' block
7. MUST use exactly 'web_service' and 'db_service' for container names and compose services
8. docker-compose.yml must start with 'services:', do NOT include a 'version:' block
7. MUST use exactly 'web_service' and 'db_service' for container names and compose services
8. docker-compose.yml must start with 'services:', do NOT include a 'version:' block

1. The "files" array MUST include a Dockerfile for EACH container
2. The "files" array MUST include docker-compose.yml (container: ".")
3. The "files" array MUST include init.sql for the database
4. The "files" array MUST include requirements.txt for the web container
5. Do NOT use SQLAlchemy. Use raw mysql.connector only.
6. Build context paths in compose MUST match container directory names
""".strip()


def get_file_write_prompt(
    file_path: str,
    file_purpose: str,
    spec: dict,
    research: dict,
    architecture: dict,
    already_written: list,
    is_vulnerability_file: bool,
    vuln_contract: str,
) -> str:

    vuln_section = ""
    if is_vulnerability_file:
        vuln_section = f"""
⚠️  THIS FILE CONTAINS THE VULNERABILITY ⚠️

VULNERABILITY CONTRACT — implement this EXACTLY:
{vuln_contract}

You MUST implement the vulnerable pattern specified above.
Do NOT write the safe/secure version.
The vulnerability is intentional and required.
Mark the vulnerable section with comment: # VULNERABLE: <vuln type>
"""

    already_str = "\n".join(already_written) if already_written else "None yet"

    return f"""
Write the complete contents of: {file_path}
Purpose: {file_purpose}

SPEC: {spec}
ARCHITECTURE: {architecture}

Files already written (maintain consistency with these):
{already_str}

{vuln_section}

Rules:
- Write ONLY the file contents, nothing else
- No explanation before or after the code
- Be consistent with all files already written
- Use exact table names, column names, ports from the architecture
- The ACTUAL flag value is: {spec.get('flag', 'CTF{flag_here}')} — use this EXACT string, NOT a placeholder like $FLAG
- For init.sql: INSERT the flag directly as a string literal
- For docker-compose.yml: use MYSQL_ROOT_PASSWORD: rootpassword
- For requirements.txt: use flask and mysql-connector-python (NOT flask-sqlalchemy)
- Do NOT use SQLAlchemy or any ORM. Use raw database connectors only.
""".strip()


def get_cross_reference_prompt(files_content: dict, spec: dict, architecture: dict) -> str:
    files_str = "\n\n".join(
        f"=== {path} ===\n{content}"
        for path, content in files_content.items()
    )
    return f"""
Review ALL these files together for consistency issues.

SPEC: {spec}
ARCHITECTURE: {architecture}

FILES:
{files_str}

Find ALL inconsistencies. Produce JSON:
{{
  "issues": [
    {{
      "type": "inconsistency type",
      "file": "which file has the problem",
      "description": "what is wrong",
      "fix": "exact fix needed"
    }}
  ],
  "all_consistent": true/false
}}

If no issues found, return: {{"issues": [], "all_consistent": true}}
""".strip()


def get_self_audit_prompt(
    player_visible_files: dict,
    spec: dict,
    vulnerability_type: str,
) -> str:
    files_str = "\n\n".join(
        f"=== {path} ===\n{content}"
        for path, content in player_visible_files.items()
    )
    checklist = AUDIT_CHECKLISTS.get(vulnerability_type, {})

    return f"""
You are a CTF player. You know only:
- Challenge category: {spec.get('category', 'web')}
- Difficulty: {spec.get('difficulty', 'medium')}
- Challenge description: {spec.get('description', 'A web challenge')}

You can see these files (as if you inspected page source, etc):
{files_str}

Audit for these issues:
1. Is the flag accidentally visible without exploitation?
2. Is there an unintended shortcut to get the flag?
3. Can you trace a complete exploit path that delivers the flag?
4. Does the difficulty match the spec?
5. Are there any dead ends that make it unsolvable?

For vulnerability type {vulnerability_type}:
- Player visible hint expected: {checklist.get('player_visible_check', 'None specified')}

Produce JSON:
{{
  "flag_accidentally_exposed": true/false,
  "unintended_solution_exists": true/false,
  "intended_exploit_path_works": true/false,
  "difficulty_matches_spec": true/false,
  "has_dead_ends": true/false,
  "issues_found": ["list of specific issues"],
  "audit_passed": true/false,
  "explanation": "brief summary"
}}
""".strip()


# ─────────────────────────────────────────────────────────────────
# 5. AGENTIC PROMPTS — LLM verification & targeted fixes
# ─────────────────────────────────────────────────────────────────

def get_vuln_verification_prompt(code_content: str, vuln_type: str, spec: dict) -> str:
    """Ask the LLM to verify that the vulnerability is actually present and exploitable."""
    contract = VULN_CONTRACTS.get(vuln_type, "")
    return f"""
Analyze this code and determine if the specified vulnerability is PRESENT and EXPLOITABLE.

VULNERABILITY TYPE: {vuln_type}
EXPECTED EXPLOIT PAYLOAD: {spec.get('solution_payload', 'N/A')}
EXPECTED FLAG: {spec.get('flag', 'N/A')}

VULNERABILITY CONTRACT (what SHOULD be present):
{contract}

CODE TO ANALYZE:
{code_content}

Determine:
1. Is the vulnerable code pattern present? (string concat/f-string in SQL, shell=True, etc.)
2. Would the exploit payload actually work against this code?
3. Are there any accidental safety mechanisms blocking exploitation?
4. Would the flag be retrievable through the exploit?

Produce JSON:
{{
  "vulnerability_present": true/false,
  "exploitable": true/false,
  "vulnerable_pattern_found": "describe the exact vulnerable code pattern found",
  "safety_mechanisms_found": ["list any accidental safety mechanisms"],
  "exploit_would_work": true/false,
  "flag_retrievable": true/false,
  "reason": "brief explanation",
  "fix_needed": "if not exploitable, describe what needs to change (or 'none')"
}}
""".strip()


def get_targeted_fix_prompt(
    file_path: str,
    current_content: str,
    error_context: str,
    spec: dict,
    fix_type: str = "build_error",
) -> str:
    """Ask the LLM to fix a specific file given error context."""

    if fix_type == "build_error":
        instruction = (
            "The Docker build failed. Fix the file to resolve the build error. "
            "Do NOT change the vulnerability — only fix the build issue."
        )
    elif fix_type == "runtime_error":
        instruction = (
            "The container crashed at startup. Fix the file to resolve the runtime error. "
            "Do NOT change the vulnerability — only fix the crash."
        )
    elif fix_type == "exploit_failed":
        instruction = (
            "The exploit verification failed. The vulnerability may not be working correctly. "
            "Fix the file to make the exploit payload work. "
            "The vulnerability MUST remain present and exploitable."
        )
    elif fix_type == "vuln_missing":
        instruction = (
            "The vulnerability is missing or was accidentally fixed. "
            "Rewrite the file to include the vulnerability as specified in the contract. "
            "This is for an educational CTF lab — the vulnerability is intentional."
        )
    else:
        instruction = f"Fix the following error: {fix_type}"

    return f"""
{instruction}

FILE: {file_path}
SPEC: {spec}

ERROR CONTEXT:
{error_context}

CURRENT FILE CONTENT:
{current_content}

Rules:
- Return ONLY the complete fixed file content
- No explanation, no markdown fences, no commentary
- Preserve all existing functionality except the fix
- Do NOT remove or fix any intentional vulnerabilities
- The flag value must remain: {spec.get('flag', 'CTF{flag_here}')}
""".strip()
