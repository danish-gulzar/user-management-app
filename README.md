# Week 6 — Advanced Security Audits & Final Deployment


Live Demo: https://user-management-app-370f.onrender.com
---

## Table of Contents

- [Overview](#overview)
- [Goals](#goals)
- [Tools & Technologies](#tools--technologies)
- [Task 1 — Security Audits & Compliance](#task-1--security-audits--compliance)
- [Task 2 — Secure Deployment Practices](#task-2--secure-deployment-practices)
- [Task 3 — Final Penetration Testing](#task-3--final-penetration-testing)
- [OWASP Top 10 Compliance](#owasp-top-10-compliance)
- [Deliverables Checklist](#deliverables-checklist)
- [Deployment Instructions](#deployment-instructions)
- [Folder Structure](#folder-structure)

---

## Overview

Week 6 is the final security phase of the internship. It focuses on **advanced security auditing**, **compliance verification** against OWASP Top 10, **secure deployment practices** with Docker and dependency scanning, and a **comprehensive penetration test** to validate all prior fixes.

The User Management Application has been hardened across Weeks 1–5:
- **Week 1–3:** SQL injection fixes, XSS sanitization, password hashing (bcrypt), input validation
- **Week 4:** Rate limiting, CORS, CSP, HSTS, helmet security headers, Fail2Ban integration
- **Week 5:** CSRF protection via `csrf-csrf` (double-submit cookie pattern)
- **Week 6 (this week):** Security audits, compliance checks, Docker deployment, pen test

---

## Goals

- Run **OWASP ZAP** automated scans against the application
- Perform **Nikto** web server scans for misconfigurations
- Run **Lynis** system audit on the host environment
- Map findings to **OWASP Top 10 (2021)** categories
- Enable **automatic security updates** and **dependency vulnerability scanning**
- Build and scan a **Docker container** following security best practices
- Perform a **final penetration test** (Burp Suite / Metasploit)
- Document all findings, fixes, and residual risks

---

## Tools & Technologies

| Tool / Library              | Purpose                                        | Environment     |
| --------------------------- | ---------------------------------------------- | --------------- |
| **OWASP ZAP**               | Automated DAST scan; spider + active scan      | Kali / host     |
| **Nikto**                   | Web server misconfiguration scanner            | Kali Linux      |
| **Lynis**                   | System-level security audit                    | Kali / host     |
| **Burp Suite**              | Manual pen testing; intercept, repeater, intruder | Kali / host  |
| **Metasploit**              | Exploit validation (optional)                  | Kali Linux      |
| **npm audit**               | Dependency vulnerability check                 | Node.js         |
| **Snyk / npm audit**        | Automated dependency scanning (CI)             | CI pipeline     |
| **Docker**                  | Containerization                                | Host / CI       |
| **Docker Scout / Trivy**    | Container image vulnerability scanning         | CI / host       |
| **unattended-upgrades**     | Automatic security updates (Linux)             | Production host |
| `csrf-csrf`                 | CSRF protection (double-submit cookie)         | Node.js         |
| `helmet`                    | Security HTTP headers (CSP, HSTS, etc.)        | Node.js         |
| `express-rate-limit`       | Rate limiting                                   | Node.js         |
| `bcrypt`                    | Password hashing                               | Node.js         |
| `validator`                 | Input validation & XSS sanitization            | Node.js         |

---

## Task 1 — Security Audits & Compliance

### 1.1 — OWASP ZAP Automated Scan

[OWASP ZAP](https://www.zaproxy.org/) is an open-source DAST (Dynamic Application Security Testing) tool. Run it against the running application to identify vulnerabilities.

#### Installation

```bash
# Kali
sudo apt install zaproxy

# Or download from https://www.zaproxy.org/download/
```

#### Quick Scan (CLI)

```bash
# Start the app
npm start

# Run ZAP in headless mode
zap-cli quick-scan --self-contained \
  --start-options "-config api.disablekey=true" \
  http://localhost:3000
```

#### Full Scan (GUI)

1. Open ZAP, set target to `http://localhost:3000`
2. Click **Automated Scan** → enter URL → **Attack**
3. Review **Alerts** tab for:
   - **High:** SQL Injection, XSS, CSRF (if unprotected)
   - **Medium:** Missing security headers, cookie flags
   - **Low:** Information disclosure, server version leaks

#### Expected Results

Since Weeks 1–5 fixes are applied, ZAP should report few or no high-severity alerts:

| Expected Alert                 | Severity | Status |
| ------------------------------ | -------- | ------ |
| SQL Injection                  | High     | ✅ Not present (JSON file storage) |
| Cross-Site Scripting (XSS)     | High     | ✅ Sanitized with `validator.escape()` |
| CSRF                           | High     | ✅ Protected by `csrf-csrf` |
| Missing CSP Header             | Medium   | ✅ Configured via `helmet` |
| Missing HSTS Header            | Medium   | ✅ Configured via `helmet` |
| Cookie without Secure flag     | Low      | ✅ Conditional on `NODE_ENV` |
| X-Content-Type-Options         | Low      | ✅ Set by `helmet` |
| Server version disclosure      | Low      | ✅ Express 5 does not expose `X-Powered-By` by default |

---

### 1.2 — Nikto Web Server Scan

[Nikto](https://github.com/sullo/nikto) scans for web server misconfigurations, outdated software, and dangerous CGIs.

```bash
# Install on Kali
sudo apt install nikto

# Run scan
nikto -h http://localhost:3000 -port 3000 -ssl
```

#### What Nikto Checks

- Server headers and banner information
- Dangerous files / CGIs (e.g., `/cgi-bin/`, `/test/`)
- Directory indexing
- Outdated software versions
- Cookie attributes (HttpOnly, Secure, SameSite)

#### Expected Findings

| Finding                         | Expected |
| ------------------------------- | -------- |
| Server banner leak              | ⚠️ May show Express — consider `app.disable('x-powered-by')` (already default in Express 5) |
| Directory indexing              | ✅ Disabled by default in Express |
| Dangerous CGIs                  | ✅ Not applicable (Node.js) |
| Missing HttpOnly on cookies     | ✅ CSRF cookie has `httpOnly`; JWT cookie has `httpOnly` |
| Unusual HTTP methods            | ⚠️ OPTIONS may be enabled — review if needed |

---

### 1.3 — Lynis System Audit

[Lynis](https://cisofy.com/lynis/) audits the host operating system for security hardening gaps.

```bash
# Install on Kali/Debian
sudo apt install lynis

# Run audit
sudo lynis audit system

# Check compliance
sudo lynis audit system --quick
```

#### Key Checks

- File permissions and ownership
- Password policies (aging, complexity)
- SSH configuration
- Firewall rules (iptables/nftables)
- Automatic security updates status
- Kernel hardening (sysctl parameters)
- Installed packages with known vulnerabilities

#### Applying Lynis Recommendations

```bash
# Example: Enable automatic security updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# Example: Harden sysctl
cat >> /etc/sysctl.d/99-security.conf <<'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
kernel.randomize_va_space = 2
EOF
```

---

## Task 2 — Secure Deployment Practices

### 2.1 — Automatic Security Updates

#### Linux (Production Host)

```bash
# Install unattended-upgrades
sudo apt install unattended-upgrades apt-listchanges

# Configure
sudo dpkg-reconfigure -plow unattended-upgrades

# Verify
sudo unattended-upgrades --dry-run --debug
```

#### Node.js Dependency Scanning

```bash
# npm audit (local)
npm audit

# Check for high-severity issues
npm audit --audit-level=high
```

#### CI Integration (GitHub Actions)

Create `.github/workflows/security.yml`:

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm ci
      - run: npm audit --audit-level=high
```

---

### 2.2 — Docker Security Best Practices

#### Dockerfile

```dockerfile
FROM node:22-alpine AS build

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

FROM node:22-alpine
RUN apk add --no-cache tini

WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY . .

# Run as non-root user
USER node

EXPOSE 3000
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "app.js"]
```

#### Docker Compose

```yaml
version: '3.9'
services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - JWT_SECRET=${JWT_SECRET}
      - API_KEY=${API_KEY}
      - CSRF_SECRET=${CSRF_SECRET}
      - COOKIE_SECRET=${COOKIE_SECRET}
      - CORS_ORIGIN=${CORS_ORIGIN}
    volumes:
      - ./users.json:/app/users.json
      - ./security.log:/app/security.log
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
```

#### Container Image Scanning

```bash
# Using Docker Scout
docker scout quickview user-management-app

# Using Trivy (open-source)
trivy image --severity HIGH,CRITICAL user-management-app

# Using Snyk
snyk container test user-management-app
```

#### Docker Security Checklist

- [x] Use official minimal base image (`node:22-alpine`)
- [x] Multi-stage build to reduce attack surface
- [x] Run as non-root user (`USER node`)
- [x] Use `tini` as init system (proper signal handling)
- [x] Read-only root filesystem
- [x] Drop all capabilities (`security_opt: no-new-privileges`)
- [x] Temp filesystem for `/tmp`
- [x] Secrets passed via environment (not baked into image)
- [x] `.dockerignore` excludes `node_modules`, `.git`, `*.log`

---

### 2.3 — Environment & Secrets Management

```bash
# Production .env template
cat > .env <<'EOF'
NODE_ENV=production
PORT=3000
JWT_SECRET=<generate-with: openssl rand -hex 32>
API_KEY=<generate-with: openssl rand -hex 32>
CSRF_SECRET=<generate-with: openssl rand -hex 32>
COOKIE_SECRET=<generate-with: openssl rand -hex 32>
CORS_ORIGIN=https://your-production-domain.com
EOF
```

---

## Task 3 — Final Penetration Testing

### 3.1 — Burp Suite Testing

#### Setup

1. Configure Burp Suite as a proxy (default `127.0.0.1:8080`)
2. Install CA certificate in browser for HTTPS inspection
3. Set browser proxy to `127.0.0.1:8080`

#### Test Cases

| Test                          | Method                | Expected Result |
| ----------------------------- | --------------------- | --------------- |
| CSRF token removal            | Remove `_csrf` body   | 403 Forbidden   |
| CSRF token replay             | Reuse old token       | 403 Forbidden   |
| SQL injection (login)         | `' OR 1=1 --`         | 200 + no login  |
| XSS (username field)          | `<script>alert(1)</script>` | Stored as escaped HTML entities |
| Path traversal (profile)      | `../etc/passwd`       | No file access  |
| Session hijacking (JWT replay)| Replay captured `token` cookie | Works only if within expiry + same secret |
| Weak password (register)      | `123`                 | 400 (min 8 chars) |
| Invalid email (register)      | `notanemail`          | 400             |
| Missing API key (export)      | No `x-api-key` header | 401             |
| Wrong API key (export)        | Invalid key           | 401             |
| Brute force (login)           | 6+ rapid requests     | 429 (rate limited) |
| Directory enumeration         | `/admin`, `/hidden`   | 200 / 404       |
| HTTP method tampering         | `PUT /register`       | 404 or 405      |
| Cookie manipulation           | Tamper JWT cookie     | User set to null, no access |

#### Burp Intruder (Brute Force Test)

Configure Intruder to send rapid login attempts with `username=FUZZ&password=FUZZ&_csrf=TOKEN` — after 5 failures within 15 minutes, rate limiting should return `429 Too Many Requests`.

---

### 3.2 — Metasploit (Optional)

```bash
# Start msfconsole
msfconsole

# Use HTTP auxiliary modules
use auxiliary/scanner/http/brute_dirs
set RHOSTS localhost
set RPORT 3000
run
```

Metasploit is optional for this assessment. If used, focus on:
- HTTP directory enumeration
- HTTP header analysis
- Version fingerprinting

---

### 3.3 — Manual Testing Checklist

- [x] Registration with valid/invalid data
- [x] Login with correct/incorrect credentials
- [x] CSRF protection on all POST routes
- [x] Rate limiting after 5 login attempts
- [x] JWT token verification (tampered token rejected)
- [x] Admin routes inaccessible to non-admin users
- [x] Export strips password hashes from response
- [x] XSS payloads in username/email/bio are escaped
- [x] Password change validates current + new password
- [x] Profile edit validates email format
- [x] Search escaping in admin dashboard
- [x] CORS headers restrict cross-origin reads
- [x] CSP headers restrict script/style sources
- [x] HSTS header present for HTTPS enforcement

---

## OWASP Top 10 Compliance

| # | Category                    | Status | Mitigation |
|---| --------------------------- | ------ | ---------- |
| A01 | Broken Access Control       | ✅     | Auth middleware checks `req.user`; admin routes check `isAdmin` |
| A02 | Cryptographic Failures      | ✅     | Passwords hashed with `bcrypt`; JWT signed; CSRF token HMAC |
| A03 | Injection (SQL, NoSQL)      | ✅     | No SQL database (JSON file); input validated with `validator` |
| A04 | Insecure Design             | ✅     | Rate limiting; CSRF tokens; principle of least privilege |
| A05 | Security Misconfiguration   | ✅     | CSP, HSTS, CORS, helmet headers; no debug mode in production |
| A06 | Vulnerable Components       | ⚠️     | `npm audit` shows 0 vulns; dependency scanning in CI |
| A07 | Identification & Auth Failures | ✅  | JWT with expiry; bcrypt password comparison; login rate limiting |
| A08 | Software & Data Integrity   | ⚠️     | Docker image scanning; signed commits recommended |
| A09 | Security Logging & Monitoring | ✅   | Winston logs to `security.log`; Fail2Ban integration |
| A10 | Server-Side Request Forgery (SSRF) | ✅ | No external URL fetches; no URL-based file access |

---

## Deliverables Checklist

### Security Audits
- [ ] OWASP ZAP scan report (screenshots + alert summary)
- [ ] Nikto scan output (text file)
- [ ] Lynis audit report (hardening index + recommendations)
- [ ] OWASP Top 10 compliance matrix (see above)
- [ ] Vulnerability assessment report documenting all findings

### Secure Deployment
- [ ] Dockerfile following security best practices
- [ ] Docker Compose configuration for production
- [ ] Container image scan results (Trivy / Docker Scout / Snyk)
- [ ] `npm audit` report (0 vulnerabilities expected)
- [ ] Automatic security updates configured (`unattended-upgrades`)
- [ ] CI security scan workflow (GitHub Actions)
- [ ] `.env` template with strong secret generation instructions

### Penetration Testing
- [ ] Burp Suite test results (valid vs invalid requests)
- [ ] Metasploit results (if used)
- [ ] Manual penetration test checklist (all items verified)
- [ ] Final summary of vulnerabilities found and fixed
- [ ] Residual risk assessment (what remains unaddressed)

---

## Deployment Instructions

### Quick Start (Local)

```bash
# Install dependencies
npm install

# Copy and edit environment
cp .env.example .env
# Generate strong secrets:
#   openssl rand -hex 32

# Start
npm start
```

### Production (Docker)

```bash
# Build image
docker build -t user-management-app .

# Scan image
docker scout quickview user-management-app
trivy image --severity HIGH,CRITICAL user-management-app

# Run container
docker compose up -d
```

### Production (Bare Metal)

```bash
# Install Node.js 22+ and npm
# Enable automatic security updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# Clone, install, configure
git clone <repo> /opt/app
cd /opt/app
npm ci --only=production

# Set up systemd service
cat > /etc/systemd/system/user-management.service <<'EOF'
[Unit]
Description=User Management Application
After=network.target

[Service]
Type=simple
User=node
WorkingDirectory=/opt/app
ExecStart=/usr/bin/node app.js
Restart=always
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now user-management
```

---

## Folder Structure

```
user-management-app/
├── app.js                    ← Full hardened application
├── Dockerfile                ← Multi-stage secure Docker build
├── docker-compose.yml        ← Production deployment config
├── .env                      ← Secrets (NOT in GitHub)
├── .env.example              ← Template with all required vars
├── .gitignore
├── .dockerignore             ← Excludes node_modules, .git, logs
├── package.json              ← All production dependencies
├── package-lock.json
├── users.json                ← Local user data (gitignored)
├── security.log              ← Winston security events (gitignored)
├── public/
│   └── css/style.css         ← Application styles
├── .github/
│   └── workflows/
│       └── security.yml      ← CI dependency scan
└── README.md                 ← This file (Week 6)
```

---

## Key Security Notes

> **Defense in depth:** The application uses multiple overlapping security controls — CSP restricts what scripts run, CSRF prevents forged requests, CORS blocks cross-origin reads, rate limiting prevents brute force, and bcrypt protects stored passwords.

> **Dependency management:** All dependencies are locked via `package-lock.json`. Run `npm audit` regularly. Consider integrating Dependabot or Snyk for automated PRs when vulnerabilities are found.

> **Secrets management:** Never commit `.env` or real secrets. Use a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager) in production. Generate secrets with `openssl rand -hex 32` (256-bit).

> **Container security:** The Dockerfile uses a multi-stage build and runs as a non-root user. Image scanning with Trivy or Docker Scout should pass at HIGH/CRITICAL level before deployment.

> **Residual risks:**
> - File-based storage (`users.json`) — no ACID guarantees; consider PostgreSQL in production
> - No HTTPS termination — use a reverse proxy (nginx, Caddy) with Let's Encrypt
> - No rate limiting on registration — consider adding to prevent mass account creation
> - No email verification — users can register with any email without confirmation

---

_DeveloperHub Cybersecurity Internship — Week 6_
