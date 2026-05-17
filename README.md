# Week 4 — API Security Hardening & Web Security Headers

---

## Table of Contents

- [Overview](#overview)
- [Goals](#goals)
- [Tools & Technologies](#tools--technologies)
- [Task 1 — API Security Hardening](#task-1--api-security-hardening)
- [Task 2 — Security Headers & CSP](#task-2--security-headers--csp)
- [Testing & Verification](#testing--verification)
- [Deliverables Checklist](#deliverables-checklist)
- [Folder Structure](#folder-structure)

---

## Overview

This branch builds upon the Week 1–3 security foundation by implementing advanced defensive security measures on the User Management Application. The focus shifts from identifying vulnerabilities to actively hardening the application against real-world attack vectors including brute-force attacks, unauthorized API access, cross-site scripting, and protocol downgrade attacks.

---

## Goals

- Harden API endpoints against brute-force and unauthorized access
- Implement industry-standard security headers
- Enforce strict Content Security Policy (CSP)
- Force HTTPS via HTTP Strict Transport Security (HSTS)

---

## Tools & Technologies

| Tool / Library       | Purpose                               | Environment   |
| -------------------- | ------------------------------------- | ------------- |
| `express-rate-limit` | API rate limiting                     | Node.js       |
| `cors`               | Cross-Origin Resource Sharing control | Node.js       |
| `helmet`             | Security headers (CSP, HSTS, etc.)   | Node.js       |
| `dotenv`             | Environment variable management       | Node.js       |
| Kali Linux VM        | Security testing environment          | VM            |
| curl                 | Header verification                   | Kali Linux VM |

---

## Task 1 — API Security Hardening

### What Was Implemented

Three layers of API security were added to the Node.js/Express application — rate limiting to prevent brute-force attacks, CORS configuration to restrict unauthorized cross-origin access, and API key authentication to protect sensitive endpoints.

---

### 1.1 — Package Installation

```bash
npm install express-rate-limit cors dotenv
```

---

### 1.2 — Rate Limiting

Two rate limiters were implemented — a global limiter for all routes and a strict limiter specifically for the login endpoint.

```javascript
const rateLimit = require("express-rate-limit");

// Global limiter — all routes
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: "Too many requests from this IP, please try again later.",
});

// Login limiter — strict, login route only
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many login attempts. Please try again after 15 minutes.",
});

app.use(globalLimiter);
```

Applied to the login route:

```javascript
app.post("/login", loginLimiter, async (req, res) => {
  // login logic
});
```

| Limiter | Window | Max Requests | Applied To    |
| ------- | ------ | ------------ | ------------- |
| Global  | 15 min | 100          | All routes    |
| Login   | 15 min | 5            | `/login` only |

---

### 1.3 — CORS Configuration

CORS was restricted to the application's own origin, preventing unauthorized cross-origin requests:

```javascript
const cors = require("cors");

const corsOptions = {
  origin: "http://localhost:3000",
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization", "x-api-key"],
};

app.use(cors(corsOptions));
```

---

### 1.4 — API Key Authentication

An API key middleware was implemented to protect sensitive endpoints. The key is stored in a `.env` file and never hardcoded.

```javascript
const apiKeyAuth = (req, res, next) => {
  const apiKey = req.headers["x-api-key"];
  if (!apiKey || apiKey !== process.env.API_KEY) {
    return res.status(401).json({ message: "Unauthorized: Invalid API Key" });
  }
  next();
};
```

Applied to the admin export endpoint:

```javascript
app.get("/admin/export", apiKeyAuth, (req, res) => {
  // export logic
});
```

`.env` file (not committed to GitHub):

```
JWT_SECRET=your-secret-key-change-in-production
API_KEY=your-secret-api-key-here
```

`.gitignore` updated:

```
.env
node_modules/
logs/
```

---

## Task 2 — Security Headers & CSP

### What Was Implemented

`helmet.js` was configured explicitly to apply a strict Content Security Policy (CSP) and HTTP Strict Transport Security (HSTS), along with other security headers that protect against common web attack vectors.

---

### 2.1 — Helmet.js Full Configuration

The basic `app.use(helmet())` was replaced with explicit configuration:

```javascript
const helmet = require("helmet");

// Base helmet — applies X-Frame-Options, X-Content-Type-Options, etc.
app.use(helmet());

// Content Security Policy — prevents XSS and script injection
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  }),
);

// HSTS — forces HTTPS for 1 year
app.use(
  helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  }),
);
```

---

### 2.2 — Security Headers Applied

| Header                      | Value                | Protection Against       |
| --------------------------- | -------------------- | ------------------------ |
| `Content-Security-Policy`   | `default-src 'self'` | XSS, script injection    |
| `Strict-Transport-Security` | `max-age=31536000`   | Protocol downgrade, MITM |
| `X-Frame-Options`           | `SAMEORIGIN`         | Clickjacking             |
| `X-Content-Type-Options`    | `nosniff`            | MIME sniffing attacks    |
| `X-DNS-Prefetch-Control`    | `off`                | Information leakage      |
| `Referrer-Policy`           | `no-referrer`        | Referrer leakage         |

---

### CSP Directive Breakdown

| Directive                 | Value                    | Meaning                                   |
| ------------------------- | ------------------------ | ----------------------------------------- |
| `defaultSrc`              | `'self'`                 | Only allow resources from same origin     |
| `scriptSrc`               | `'self'`                 | No inline scripts, no external scripts    |
| `styleSrc`                | `'self' 'unsafe-inline'` | Allow inline styles (required for app UI) |
| `imgSrc`                  | `'self' data:`           | Images from same origin + base64          |
| `objectSrc`               | `'none'`                 | Block all plugins (Flash, etc.)           |
| `upgradeInsecureRequests` | —                        | Auto-upgrade HTTP to HTTPS                |

---

## Testing & Verification

### Header Verification via curl (from Kali VM)

```bash
curl -I http://<windows-ip>:3000
```

Output confirmed the following headers were present:

```
HTTP/1.1 200 OK
Content-Security-Policy: default-src 'self';script-src 'self';...
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-DNS-Prefetch-Control: off
Referrer-Policy: no-referrer
```

---

### Rate Limiting Verification

Triggered 6 rapid login requests to `/login`. After the 5th attempt, the server responded:

```
HTTP/1.1 429 Too Many Requests
Too many login attempts. Please try again after 15 minutes.
```

---

### API Key Verification

Request without API key:

```bash
curl http://localhost:3000/admin/export
# Response: 401 Unauthorized: Invalid API Key
```

Request with correct API key:

```bash
curl -H "x-api-key: your-secret-api-key-here" http://localhost:3000/admin/export
# Response: 200 OK with data
```

---

## Deliverables Checklist

- [x] Global rate limiter applied (100 req / 15 min)
- [x] Login-specific rate limiter applied (5 req / 15 min)
- [x] CORS restricted to `localhost:3000`
- [x] API key middleware protecting `/admin/export`
- [x] `.env` file with `API_KEY` (not committed to GitHub)
- [x] `.env` added to `.gitignore`
- [x] Explicit CSP configured via `helmet.contentSecurityPolicy`
- [x] HSTS configured via `helmet.hsts` (1 year, preload)
- [x] All headers verified via `curl` from Kali VM
- [x] Rate limiting verified (429 response after 5 attempts)
- [x] All changes committed to `week4-6-security` branch

---

## Folder Structure

```
user-management-app/
├── app.js          ← Main application with all Week 4 security
├── .env            ← API keys and secrets (NOT in GitHub)
├── .gitignore      ← Excludes .env, node_modules, logs
├── package.json
└── README.md       ← This file
```

---

## Key Security Notes

> **JWT Token:** JWT is generated on login but route-level authentication currently uses a server-side `currentUser` variable. This is a known limitation documented for future improvement. API key authentication has been applied to sensitive admin endpoints as a compensating control.

> **HTTPS:** HSTS header is configured and active. Full HTTPS enforcement requires an SSL certificate which is outside the scope of the local development environment used in this internship.

---

_DeveloperHub Cybersecurity Internship — Week 4_
