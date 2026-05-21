require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const winston = require('winston');

const rateLimit = require('express-rate-limit');
const cors = require('cors');

const COOKIE_SECRET = process.env.COOKIE_SECRET || 'your-cookie-secret-change-in-production';

const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});

// helmetjs to secure HTTP headers (VULNERABILITY 5 context: adds security headers)
const helmet = require('helmet');

const app = express();
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https://api.dicebear.com"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    }
  })
);
app.set('view engine', 'ejs');

// ============================================
// WEEK 5: CSRF PROTECTION
// ============================================
// Cross-Site Request Forgery (CSRF) protection using csurf middleware (Week 5 task).
// Double-submit cookie pattern: csurf stores a secret in the _csrf cookie; every
// state-changing POST must include a matching token in the form body or request header.
// Test with Burp Suite by attempting forged requests without a valid token.
const cookieParser = require('cookie-parser');
const csrf = require('csurf');

app.use(cookieParser(COOKIE_SECRET));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(csrf({ cookie: { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production' } }));

// WEEK 5: Embed hidden _csrf field in HTML forms served to the browser
function getCsrfField(req) {
  return `<input type="hidden" name="_csrf" value="${req.csrfToken()}">`;
}

// Global limiter - applies to all routes
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});

// Login limiter - stricter, only for /login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts. Please try again after 15 minutes.'
});

app.use(globalLimiter);

const corsOptions = {
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key', 'x-csrf-token'],
  credentials: true
};

app.use(cors(corsOptions));

const apiKeyAuth = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== process.env.API_KEY) {
    return res.status(401).json({ message: 'Unauthorized: Invalid API Key' });
  }
  next();
};

// NOTE: CSP is handled above via helmet() — no duplicate header needed here

// Persistent storage - load users from file on startup
const USERS_FILE = path.join(__dirname, 'users.json');

function loadUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      const data = fs.readFileSync(USERS_FILE, 'utf8');
      return JSON.parse(data);
    }
  } catch (err) {
    console.error('Error loading users file:', err);
  }
  return [];
}

function saveUsers(usersArray) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(usersArray, null, 2));
  } catch (err) {
    console.error('Error saving users file:', err);
  }
}

// In-memory "database" (synced with file)
let users = loadUsers();

// Helper: Generate avatar initials
function getInitials(username) {
  return username && username.length > 0 ? username.charAt(0).toUpperCase() : '?';
}

// Helper: Get navbar HTML
function getNavbar(user) {
  if (user) {
    return `
      <nav class="navbar">
        <a href="/" class="navbar-brand">UserManager</a>
        <div class="navbar-links">
          <a href="/">Home</a>
          <a href="/dashboard">Dashboard</a>
          <a href="/profile?user=${user.username}">Profile</a>
          ${user.isAdmin ? '<a href="/admin">Admin</a>' : ''}
          <div class="navbar-user">
            <div class="navbar-avatar">${getInitials(user.username)}</div>
            <span>${user.username}</span>
          </div>
          <a href="/logout" class="btn btn-secondary btn-small">Logout</a>
        </div>
      </nav>
    `;
  }
  return `
    <nav class="navbar">
      <a href="/" class="navbar-brand">UserManager</a>
      <div class="navbar-links">
        <a href="/">Home</a>
        <a href="/login">Login</a>
        <a href="/register" class="btn btn-primary btn-small">Register</a>
      </div>
    </nav>
  `;
}

// DASHBOARD (for logged-in users)
app.get('/dashboard', (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }

  const sortedUsers = [...users].sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  const userStats = {
    totalUsers: users.length,
    myRank: sortedUsers.findIndex(u => u.username === req.user.username) + 1,
    daysSinceJoined: Math.floor((Date.now() - new Date(req.user.createdAt)) / (1000 * 60 * 60 * 24)),
    profileComplete: !!req.user.bio && !!req.user.email
  };

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="dashboard-container">
    <div class="dashboard-header">
      <h1>My Dashboard</h1>
      <p>Welcome back, ${req.user.username}!</p>
    </div>

    <div class="dashboard-stats">
      <div class="dashboard-stat-card">
        <div class="stat-icon">👤</div>
        <div class="stat-value">${userStats.totalUsers}</div>
        <div class="stat-label">Total Users</div>
      </div>
      <div class="dashboard-stat-card">
        <div class="stat-icon">📊</div>
        <div class="stat-value">#${userStats.myRank}</div>
        <div class="stat-label">Your Rank</div>
      </div>
      <div class="dashboard-stat-card">
        <div class="stat-icon">📅</div>
        <div class="stat-value">${userStats.daysSinceJoined}</div>
        <div class="stat-label">Days Since Joined</div>
      </div>
      <div class="dashboard-stat-card">
        <div class="stat-icon">${userStats.profileComplete ? '✅' : '⚠️'}</div>
        <div class="stat-value">${userStats.profileComplete ? '100%' : 'Incomplete'}</div>
        <div class="stat-label">Profile Complete</div>
      </div>
    </div>

    <div class="dashboard-grid">
      <div class="dashboard-card">
        <h3>Quick Actions</h3>
        <div class="quick-actions">
          <a href="/profile?user=${req.user.username}" class="action-btn">
            <span class="action-icon">👁️</span>
            <span>View Profile</span>
          </a>
          <a href="/profile/edit" class="action-btn">
            <span class="action-icon">✏️</span>
            <span>Edit Profile</span>
          </a>
          <a href="/password/change" class="action-btn">
            <span class="action-icon">🔐</span>
            <span>Change Password</span>
          </a>
        </div>
      </div>

      <div class="dashboard-card">
        <h3>Account Info</h3>
        <div class="account-info">
          <div class="info-row">
            <span class="info-label">Username:</span>
            <span class="info-value">${req.user.username}</span>
          </div>
          <div class="info-row">
            <span class="info-label">Email:</span>
            <span class="info-value">${req.user.email}</span>
          </div>
          <div class="info-row">
            <span class="info-label">Role:</span>
            <span class="info-value" style="color: ${req.user.isAdmin ? '#a5b4fc' : '#888'}">${req.user.isAdmin ? 'Admin' : 'User'}</span>
          </div>
          <div class="info-row">
            <span class="info-label">Member Since:</span>
            <span class="info-value">${new Date(req.user.createdAt).toLocaleDateString()}</span>
          </div>
          <div class="info-row">
            <span class="info-label">Last Login:</span>
            <span class="info-value">${req.user.lastLogin ? new Date(req.user.lastLogin).toLocaleString() : 'First login'}</span>
          </div>
        </div>
      </div>
    </div>

    ${req.user.isAdmin ? `
    <div class="dashboard-card admin-quick">
      <h3>Admin Quick Access</h3>
      <p style="color: #888; margin-bottom: 15px;">Jump to the admin dashboard to manage users.</p>
      <a href="/admin" class="btn btn-primary">Go to Admin Dashboard</a>
    </div>
    ` : ''}
  </div>
</body>
</html>`);
});

// HOME
app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>User Management</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="container" style="margin-top: 80px;">
    <div class="card">
      <h1>Welcome</h1>
      <p class="welcome-text">Manage your account with ease</p>
      <div class="links">
        <a href="/register" class="btn btn-primary">Register</a>
        <a href="/login" class="btn btn-secondary">Login</a>
      </div>
    </div>
  </div>
</body>
</html>`);
});

// REGISTER
app.get('/register', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Register</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="container" style="margin-top: 80px;">
    <div class="card">
      <h2>Create Account</h2>
      <form method="POST" action="/register">
        ${getCsrfField(req)}
        <div class="form-group">
          <label for="email">Email</label>
          <input type="email" id="email" name="email" required>
        </div>
        <div class="form-group">
          <label for="username">Username</label>
          <input type="text" id="username" name="username" required>
        </div>
        <div class="form-group">
          <label for="password">Password</label>
          <input type="password" id="password" name="password" required>
        </div>
        <div class="form-group">
          <label for="bio">Bio</label>
          <input type="text" id="bio" name="bio">
        </div>
        <button type="submit" class="btn btn-primary">Register</button>
      </form>
      <div class="back-link">
        <a href="/login">Already have an account? Login</a>
      </div>
    </div>
  </div>
</body>
</html>`);
});


// VULNERABILITY 1 Fixed: Password stored in hash not the plain text
// VULNERABILITY 2 Fixed: input validation via validator
// VULNERABILITY 5 Fixed: XSS - bio sanitized with validator.escape() before saving
const bcrypt = require('bcrypt');
const validator = require('validator');

// WEEK 5: csurf validates the _csrf token before this handler runs
app.post('/register', async (req, res) => {
  const { email, username, password, bio } = req.body;

  // VULNERABILITY 2 Fixed: Validate all inputs before processing
  if (!validator.isEmail(email)) {
    return res.status(400).send('Invalid email address');
  }
  if (validator.isEmpty(username.trim())) {
    return res.status(400).send('Username cannot be empty');
  }
  if (password.length < 6) {
    return res.status(400).send('Password must be at least 6 characters');
  }

  // VULNERABILITY 1 Fixed: Hash password — never store plain text
  const hashedPassword = await bcrypt.hash(password, 10);

  // VULNERABILITY 5 Fixed: Sanitize bio to prevent XSS
  // validator.escape() converts <script>alert('XSS')</script> to safe HTML entities
  const safeBio = validator.escape(bio || '');

  const newUser = {
    email,
    username,
    password: hashedPassword, // store the hash, never plain text
    bio: safeBio,
    createdAt: new Date().toISOString(),
    lastLogin: null,
    isAdmin: false
  };

  // Check for duplicate username
  if (users.some(u => u.username === username)) {
    return res.status(400).send('Username already exists');
  }

  // Make first user admin automatically
  if (users.length === 0) {
    newUser.isAdmin = true;
  }
  users.push(newUser);
  saveUsers(users);
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Registration Successful</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="container" style="margin-top: 80px;">
    <div class="card">
      <div class="message success">User ${username} registered successfully!</div>
      <div class="links">
        <a href="/login" class="btn btn-primary">Proceed to Login</a>
        <a href="/" class="btn btn-secondary">Back to Home</a>
      </div>
    </div>
  </div>
</body>
</html>`);
});

// LOGIN
app.get('/login', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="container" style="margin-top: 80px;">
    <div class="card">
      <h2>Login</h2>
      <form method="POST" action="/login">
        ${getCsrfField(req)}
        <div class="form-group">
          <label for="username">Username</label>
          <input type="text" id="username" name="username" required>
        </div>
        <div class="form-group">
          <label for="password">Password</label>
          <input type="password" id="password" name="password" required>
        </div>
        <button type="submit" class="btn btn-primary">Login</button>
      </form>
      <div class="back-link">
        <a href="/register">Don't have an account? Register</a>
      </div>
    </div>
  </div>
</body>
</html>`);
});
// VULNERABILITY 3 Fixed: Compare password against the stored hash
// VULNERABILITY 4 Fixed: Issue a JWT token for secure session
const jwt = require('jsonwebtoken');
const SECRET_KEY = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Auth middleware: verify JWT from cookie and attach user to req
const authMiddleware = (req, res, next) => {
  const token = req.cookies.token;
  if (token) {
    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      req.user = users.find(u => u.username === decoded.username) || null;
    } catch {
      req.user = null;
    }
  } else {
    req.user = null;
  }
  next();
};

app.use(authMiddleware);

// WEEK 5: csurf validates the _csrf token before this handler runs
app.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login Failed</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="container" style="margin-top: 80px;">
    <div class="card">
      <div class="message error">Invalid credentials</div>
      <div class="links">
        <a href="/login" class="btn btn-primary">Try Again</a>
        <a href="/" class="btn btn-secondary">Back to Home</a>
      </div>
    </div>
  </div>
</body>
</html>`);
  }

  // VULNERABILITY 3 Fixed: Use bcrypt.compare() — not plain text comparison
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login Failed</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="container" style="margin-top: 80px;">
    <div class="card">
      <div class="message error">Invalid credentials</div>
      <div class="links">
        <a href="/login" class="btn btn-primary">Try Again</a>
        <a href="/" class="btn btn-secondary">Back to Home</a>
      </div>
    </div>
  </div>
</body>
</html>`);
  }

  req.user = user;
  user.lastLogin = new Date().toISOString();

  // VULNERABILITY 4 Fixed: Issue a signed JWT token for session management
  const token = jwt.sign(
    { username: user.username },
    SECRET_KEY,
    { expiresIn: '1h' }
  );
  res.cookie('token', token, { httpOnly: true, sameSite: 'strict', maxAge: 3600000 });

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Welcome</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="container" style="margin-top: 80px;">
    <div class="card">
      <div class="message success">Welcome back, ${username}!</div>
      <div class="links">
        <a href="/dashboard" class="btn btn-primary">Go to Dashboard</a>
        <a href="/profile?user=${username}" class="btn btn-secondary">View Profile</a>
        ${user.isAdmin ? '<a href="/admin" class="btn btn-secondary">Admin Dashboard</a>' : ''}
        <a href="/" class="btn btn-secondary">Back to Home</a>
      </div>
    </div>
  </div>
</body>
</html>`);
});

// LOGOUT
app.get('/logout', (req, res) => {
  req.user = null;
  res.clearCookie('token');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Logged Out</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="container" style="margin-top: 80px;">
    <div class="card">
      <div class="message success">You have been logged out</div>
      <div class="links">
        <a href="/login" class="btn btn-primary">Login Again</a>
        <a href="/" class="btn btn-secondary">Back to Home</a>
      </div>
    </div>
  </div>
</body>
</html>`);
});

// PROFILE
// VULNERABILITY 5 Fixed: XSS - bio is sanitized via validator.escape() before saving
// Bio values stored as HTML entities — <script> cannot execute
app.get('/profile', (req, res) => {
  const username = req.query.user;
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>User Not Found</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="container" style="margin-top: 80px;">
    <div class="card">
      <div class="message error">User not found</div>
      <div class="links">
        <a href="/" class="btn btn-primary">Back to Home</a>
      </div>
    </div>
  </div>
</body>
</html>`);
  }

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Profile - ${user.username}</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="container" style="margin-top: 80px;">
    <div class="card">
      <h2>User Profile</h2>
      <div style="display: flex; justify-content: center; margin-bottom: 25px;">
        <div class="avatar" style="width: 80px; height: 80px; font-size: 2rem;">${getInitials(user.username)}</div>
      </div>
      <div class="profile-info">
        <div class="profile-item">
          <span class="profile-label">Username</span>
          <span class="profile-value">${user.username}</span>
        </div>
        <div class="profile-item">
          <span class="profile-label">Email</span>
          <span class="profile-value">${user.email}</span>
        </div>
        <div class="profile-item">
          <span class="profile-label">Bio</span>
          <span class="profile-value">${user.bio || 'No bio yet'}</span>
        </div>
        <div class="profile-item">
          <span class="profile-label">Member Since</span>
          <span class="profile-value">${new Date(user.createdAt).toLocaleDateString()}</span>
        </div>
        <div class="profile-item">
          <span class="profile-label">Last Login</span>
          <span class="profile-value">${user.lastLogin ? new Date(user.lastLogin).toLocaleString() : 'Never'}</span>
        </div>
      </div>
      <div class="form-actions" style="margin-top: 25px;">
        <a href="/profile/edit" class="btn btn-primary">Edit Profile</a>
        <a href="/password/change" class="btn btn-secondary">Change Password</a>
      </div>
      <div class="back-link">
        <a href="/">Back to Home</a>
      </div>
    </div>
  </div>
</body>
</html>`);
});

// EDIT PROFILE
app.get('/profile/edit', (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Edit Profile</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="container" style="margin-top: 80px;">
    <div class="card">
      <h2>Edit Profile</h2>
      <form method="POST" action="/profile/edit">
        ${getCsrfField(req)}
        <div class="form-group">
          <label for="email">Email</label>
          <input type="email" id="email" name="email" value="${req.user.email}" required>
        </div>
        <div class="form-group">
          <label for="bio">Bio</label>
          <input type="text" id="bio" name="bio" value="${req.user.bio || ''}">
        </div>
        <button type="submit" class="btn btn-primary">Save Changes</button>
      </form>
      <div class="back-link">
        <a href="/profile?user=${req.user.username}">Cancel</a>
      </div>
    </div>
  </div>
</body>
</html>`);
});

app.post('/profile/edit', (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }
  const { email, bio } = req.body;
  req.user.email = email;
  // VULNERABILITY 5 Fixed: Also sanitize bio on profile edit to prevent XSS
  req.user.bio = validator.escape(bio || '');
  saveUsers(users);
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Profile Updated</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="container" style="margin-top: 80px;">
    <div class="card">
      <div class="message success">Profile updated successfully!</div>
      <div class="links">
        <a href="/profile?user=${req.user.username}" class="btn btn-primary">View Profile</a>
        <a href="/" class="btn btn-secondary">Back to Home</a>
      </div>
    </div>
  </div>
</body>
</html>`);
});

// CHANGE PASSWORD
app.get('/password/change', (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Change Password</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="container" style="margin-top: 80px;">
    <div class="card">
      <h2>Change Password</h2>
      <form method="POST" action="/password/change">
        ${getCsrfField(req)}
        <div class="form-group">
          <label for="currentPassword">Current Password</label>
          <input type="password" id="currentPassword" name="currentPassword" required>
        </div>
        <div class="form-group">
          <label for="newPassword">New Password</label>
          <input type="password" id="newPassword" name="newPassword" required>
        </div>
        <div class="form-group">
          <label for="confirmPassword">Confirm New Password</label>
          <input type="password" id="confirmPassword" name="confirmPassword" required>
        </div>
        <button type="submit" class="btn btn-primary">Change Password</button>
      </form>
      <div class="back-link">
        <a href="/profile?user=${req.user.username}">Cancel</a>
      </div>
    </div>
  </div>
</body>
</html>`);
});

app.post('/password/change', async (req, res) => {
  if (!req.user) {
    return res.redirect('/login');
  }
  const { currentPassword, newPassword, confirmPassword } = req.body;
  // VULNERABILITY: Plain text password comparison — fixed to use bcrypt.compare()
  const isMatch = await bcrypt.compare(currentPassword, req.user.password);
  if (!isMatch) {
    return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Error</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="container" style="margin-top: 80px;">
    <div class="card">
      <div class="message error">Current password is incorrect</div>
      <div class="links">
        <a href="/password/change" class="btn btn-primary">Try Again</a>
        <a href="/profile?user=${req.user.username}" class="btn btn-secondary">Back to Profile</a>
      </div>
    </div>
  </div>
</body>
</html>`);
  }
  if (newPassword !== confirmPassword) {
    return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Error</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="container" style="margin-top: 80px;">
    <div class="card">
      <div class="message error">New passwords do not match</div>
      <div class="links">
        <a href="/password/change" class="btn btn-primary">Try Again</a>
        <a href="/profile?user=${req.user.username}" class="btn btn-secondary">Back to Profile</a>
      </div>
    </div>
  </div>
</body>
</html>`);
  }
  // VULNERABILITY: Password stored in plain text — fixed to hash before saving
  req.user.password = await bcrypt.hash(newPassword, 10);
  saveUsers(users);
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Password Changed</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="container" style="margin-top: 80px;">
    <div class="card">
      <div class="message success">Password changed successfully!</div>
      <div class="links">
        <a href="/profile?user=${req.user.username}" class="btn btn-primary">Back to Profile</a>
        <a href="/" class="btn btn-secondary">Back to Home</a>
      </div>
    </div>
  </div>
</body>
</html>`);
});

// ADMIN DASHBOARD
app.get('/admin', (req, res) => {
  if (!req.user || !req.user.isAdmin) {
    return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access Denied</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="container" style="margin-top: 80px;">
    <div class="card">
      <div class="message error">Access denied. Admin privileges required.</div>
      <div class="links">
        <a href="/" class="btn btn-primary">Back to Home</a>
      </div>
    </div>
  </div>
</body>
</html>`);
  }

  const searchTerm = req.query.search || '';
  const escapedSearchTerm = validator.escape(searchTerm);
  const filteredUsers = searchTerm
    ? users.filter(u => u.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
                        u.email.toLowerCase().includes(searchTerm.toLowerCase()))
    : users;

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Dashboard</title>
  <link rel="stylesheet" href="/css/style.css">
  <meta name="csrf-token" content="${req.csrfToken()}">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="admin-container">
    <div class="admin-header">
      <div>
        <h1>Admin Dashboard</h1>
        <p style="color: #888;">Manage users and system settings</p>
      </div>
      <div class="admin-stats">
        <div class="stat-badge">Total Users: ${users.length}</div>
        <div class="stat-badge">Admins: ${users.filter(u => u.isAdmin).length}</div>
        <a href="/admin/users/add" class="btn btn-primary">+ Add User</a>
      </div>
    </div>

    <form class="search-bar" method="GET" action="/admin">
      <input type="text" name="search" placeholder="Search by username or email..." value="${escapedSearchTerm}">
      <button type="submit" class="btn btn-primary">Search</button>
      ${searchTerm ? '<a href="/admin" class="btn btn-secondary">Clear</a>' : ''}
    </form>

    <div class="table-card">
      <table class="user-table">
        <thead>
          <tr>
            <th>User</th>
            <th>Email</th>
            <th>Role</th>
            <th>Joined</th>
            <th>Last Login</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${filteredUsers.length === 0 ? `
            <tr>
              <td colspan="6" style="text-align: center; padding: 40px; color: #888;">
                ${searchTerm ? 'No users found matching your search' : 'No users registered yet'}
              </td>
            </tr>
          ` : filteredUsers.map(user => `
            <tr>
              <td>
                <div class="table-cell-avatar">
                  <div class="avatar avatar-small">${getInitials(user.username)}</div>
                  <span class="username">${user.username}</span>
                </div>
              </td>
              <td><span class="email">${user.email}</span></td>
              <td>
                <span style="padding: 4px 10px; border-radius: 12px; font-size: 0.8rem; ${user.isAdmin ? 'background: rgba(102, 126, 234, 0.3); color: #a5b4fc;' : 'background: rgba(255, 255, 255, 0.1); color: #888;'}">
                  ${user.isAdmin ? 'Admin' : 'User'}
                </span>
              </td>
              <td><span class="date">${new Date(user.createdAt).toLocaleDateString()}</span></td>
              <td><span class="date">${user.lastLogin ? new Date(user.lastLogin).toLocaleDateString() : 'Never'}</span></td>
              <td>
                <div class="user-table-actions">
                  <a href="/profile?user=${user.username}" class="btn btn-small btn-view">View</a>
                  <a href="/admin/users/${user.username}/edit" class="btn btn-small btn-edit">Edit</a>
                  <a href="/admin/users/${user.username}/delete" class="btn btn-small btn-danger">Delete</a>
                </div>
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>

    <div class="data-section">
      <h3>Data Management</h3>
      <div class="data-actions">
        <a href="/admin/export" class="btn btn-primary">Export Users (JSON)</a>
        <a href="/admin/export?format=csv" class="btn btn-primary">Export Users (CSV)</a>
        <div class="file-input-wrapper">
          <button class="btn btn-secondary">Import Users</button>
          <input type="file" id="importFile" accept=".json,.csv" onchange="importUsers(this)">
        </div>
        <a href="/admin/reset-all" class="btn btn-danger">Reset All Users</a>
      </div>
    </div>
  </div>
</body>
</html>
<script src="/js/admin.js"></script>
`);
});

// DELETE USER CONFIRMATION
app.get('/admin/users/:username/delete', (req, res) => {
  if (!req.user || !req.user.isAdmin) {
    return res.redirect('/login');
  }
  const user = users.find(u => u.username === req.params.username);
  if (!user) {
    return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>User Not Found</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="admin-container" style="margin-top: 80px;">
    <div class="container">
      <div class="card">
        <div class="message error">User not found</div>
        <a href="/admin" class="btn btn-primary">Back to Admin</a>
      </div>
    </div>
  </div>
</body>
</html>`);
  }
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Delete User</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="admin-container" style="margin-top: 80px;">
    <div class="container">
      <div class="card confirm-card">
        <div class="confirm-warning">⚠️</div>
        <h2>Delete User?</h2>
        <p style="color: #a0a0a0; margin: 20px 0;">Are you sure you want to delete the following user?</p>
        <div class="confirm-details">
          <p><strong>Username:</strong> ${user.username}</p>
          <p><strong>Email:</strong> ${user.email}</p>
          <p><strong>Member since:</strong> ${new Date(user.createdAt).toLocaleDateString()}</p>
        </div>
        <p style="color: #ef4444; font-size: 0.9rem;">This action cannot be undone.</p>
        <form method="POST" action="/admin/users/${user.username}/delete" style="margin-top: 25px;">
          ${getCsrfField(req)}
          <div class="form-actions">
            <button type="submit" class="btn btn-danger">Yes, Delete User</button>
            <a href="/admin" class="btn btn-secondary">Cancel</a>
          </div>
        </form>
      </div>
    </div>
  </div>
</body>
</html>`);
});

app.post('/admin/users/:username/delete', (req, res) => {
  if (!req.user || !req.user.isAdmin) {
    return res.redirect('/login');
  }
  const username = req.params.username;
  const deletedSelf = req.user && req.user.username === username;
  users = users.filter(u => u.username !== username);
  if (deletedSelf) {
    req.user = null;
    res.clearCookie('token');
  }
  saveUsers(users);
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>User Deleted</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="admin-container" style="margin-top: 80px;">
    <div class="container">
      <div class="card">
        <div class="message success">User ${username} has been deleted</div>
        <div class="links">
          <a href="/admin" class="btn btn-primary">Back to Admin Dashboard</a>
          <a href="/" class="btn btn-secondary">Back to Home</a>
        </div>
      </div>
    </div>
  </div>
</body>
</html>`);
});

// EDIT USER
app.get('/admin/users/:username/edit', (req, res) => {
  if (!req.user || !req.user.isAdmin) {
    return res.redirect('/login');
  }
  const user = users.find(u => u.username === req.params.username);
  if (!user) {
    return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>User Not Found</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="admin-container" style="margin-top: 80px;">
    <div class="container">
      <div class="card">
        <div class="message error">User not found</div>
        <a href="/admin" class="btn btn-primary">Back to Admin</a>
      </div>
    </div>
  </div>
</body>
</html>`);
  }
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Edit User</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="admin-container" style="margin-top: 80px;">
    <div class="container">
      <div class="card">
        <h2>Edit User: ${user.username}</h2>
        <form method="POST" action="/admin/users/${user.username}/edit">
          ${getCsrfField(req)}
          <div class="form-row">
            <div class="form-group">
              <label for="username">Username</label>
              <input type="text" id="username" name="username" value="${user.username}" required>
            </div>
            <div class="form-group">
              <label for="email">Email</label>
              <input type="email" id="email" name="email" value="${user.email}" required>
            </div>
          </div>
          <div class="form-group">
            <label for="password">Password (leave blank to keep current)</label>
            <input type="password" id="password" name="password" placeholder="New password">
          </div>
          <div class="form-group">
            <label for="bio">Bio</label>
            <input type="text" id="bio" name="bio" value="${user.bio || ''}">
          </div>
          <div class="form-group">
            <label for="role">Role</label>
            <select id="role" name="isAdmin" style="padding: 14px 16px; border-radius: 10px; border: 1px solid rgba(255,255,255,0.1); background: rgba(255,255,255,0.05); color: #fff; font-size: 1rem; width: 100%;">
              <option value="false" ${!user.isAdmin ? 'selected' : ''}>User</option>
              <option value="true" ${user.isAdmin ? 'selected' : ''}>Admin</option>
            </select>
          </div>
          <div class="form-actions">
            <button type="submit" class="btn btn-primary">Save Changes</button>
            <a href="/admin" class="btn btn-secondary">Cancel</a>
          </div>
        </form>
      </div>
    </div>
  </div>
</body>
</html>`);
});

app.post('/admin/users/:username/edit', async (req, res) => {
  if (!req.user || !req.user.isAdmin) {
    return res.redirect('/login');
  }
  const { username, email, password, bio, isAdmin } = req.body;
  const user = users.find(u => u.username === req.params.username);
  if (!user) {
    return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>User Not Found</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="admin-container" style="margin-top: 80px;">
    <div class="container">
      <div class="card">
        <div class="message error">User not found</div>
        <a href="/admin" class="btn btn-primary">Back to Admin</a>
      </div>
    </div>
  </div>
</body>
</html>`);
  }
  user.username = username;
  user.email = email;
  if (password) {
    user.password = await bcrypt.hash(password, 10); // Fixed: hash password before saving
  }
  user.bio = validator.escape(bio || '');
  user.isAdmin = isAdmin === 'true';
  // BUG FIX: If admin edits their own account, update req.user reference
  // so the navbar and session reflect the new data immediately
  if (req.user && req.user.username === req.params.username) {
    req.user = user;
  }
  saveUsers(users);
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>User Updated</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="admin-container" style="margin-top: 80px;">
    <div class="container">
      <div class="card">
        <div class="message success">User ${username} updated successfully!</div>
        <div class="links">
          <a href="/admin" class="btn btn-primary">Back to Admin Dashboard</a>
          <a href="/profile?user=${username}" class="btn btn-secondary">View Profile</a>
        </div>
      </div>
    </div>
  </div>
</body>
</html>`);
});

// ADD NEW USER (Admin only)
// BUG FIX: This route MUST be declared before /admin/users/:username/edit
// Otherwise Express matches 'add' as the :username param and never reaches this handler
app.get('/admin/users/add', (req, res) => {
  if (!req.user || !req.user.isAdmin) {
    return res.redirect('/login');
  }
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Add New User</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="admin-container" style="margin-top: 80px;">
    <div class="container">
      <div class="card">
        <h2>Add New User</h2>
        <form method="POST" action="/admin/users/add">
          ${getCsrfField(req)}
          <div class="form-row">
            <div class="form-group">
              <label for="username">Username *</label>
              <input type="text" id="username" name="username" required placeholder="Enter username">
            </div>
            <div class="form-group">
              <label for="email">Email *</label>
              <input type="email" id="email" name="email" required placeholder="Enter email address">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label for="password">Password *</label>
              <input type="password" id="password" name="password" required placeholder="Enter password">
            </div>
            <div class="form-group">
              <label for="confirmPassword">Confirm Password *</label>
              <input type="password" id="confirmPassword" name="confirmPassword" required placeholder="Confirm password">
            </div>
          </div>
          <div class="form-group">
            <label for="bio">Bio</label>
            <input type="text" id="bio" name="bio" placeholder="Optional user bio">
          </div>
          <div class="form-group">
            <label for="role">Role</label>
            <select id="role" name="isAdmin" style="padding: 14px 16px; border-radius: 10px; border: 1px solid rgba(255,255,255,0.1); background: rgba(255,255,255,0.05); color: #fff; font-size: 1rem; width: 100%;">
              <option value="false">User</option>
              <option value="true">Admin</option>
            </select>
          </div>
          <div class="form-actions">
            <button type="submit" class="btn btn-primary">Add User</button>
            <a href="/admin" class="btn btn-secondary">Cancel</a>
          </div>
        </form>
      </div>
    </div>
  </div>
</body>
</html>`);
});

app.post('/admin/users/add', async (req, res) => {
  if (!req.user || !req.user.isAdmin) {
    return res.redirect('/login');
  }
  const { username, email, password, confirmPassword, bio, isAdmin } = req.body;

  // Check if username already exists
  if (users.some(u => u.username === username)) {
    return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Error</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="admin-container" style="margin-top: 80px;">
    <div class="container">
      <div class="card">
        <div class="message error">Username "${username}" already exists</div>
        <div class="links">
          <a href="/admin/users/add" class="btn btn-primary">Try Again</a>
          <a href="/admin" class="btn btn-secondary">Back to Admin</a>
        </div>
      </div>
    </div>
  </div>
</body>
</html>`);
  }

  // Check passwords match
  if (password !== confirmPassword) {
    return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Error</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="admin-container" style="margin-top: 80px;">
    <div class="container">
      <div class="card">
        <div class="message error">Passwords do not match</div>
        <div class="links">
          <a href="/admin/users/add" class="btn btn-primary">Try Again</a>
          <a href="/admin" class="btn btn-secondary">Back to Admin</a>
        </div>
      </div>
    </div>
  </div>
</body>
</html>`);
  }

  const hashedPassword = await bcrypt.hash(password, 10); // Fixed: hash password before saving
  const newUser = {
    email,
    username,
    password: hashedPassword,
    bio: validator.escape(bio || ''),
    createdAt: new Date().toISOString(),
    lastLogin: null,
    isAdmin: isAdmin === 'true'
  };

  users.push(newUser);
  saveUsers(users);

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>User Added</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="admin-container" style="margin-top: 80px;">
    <div class="container">
      <div class="card">
        <div class="message success">User ${username} added successfully!</div>
        <div class="links">
          <a href="/admin" class="btn btn-primary">Back to Admin Dashboard</a>
          <a href="/admin/users/add" class="btn btn-secondary">Add Another User</a>
        </div>
      </div>
    </div>
  </div>
</body>
</html>`);
});

// EXPORT USERS

// Export supports dual auth: session (browser) or API key (programmatic)
app.get('/admin/export', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  const isAuthenticated = (req.user && req.user.isAdmin) || (apiKey && apiKey === process.env.API_KEY);
  if (!isAuthenticated) {
    return res.status(401).json({ message: 'Unauthorized: login or provide a valid API key' });
  }
  const format = req.query.format || 'json';
  if (format === 'csv') {
    const csv = 'username,email,bio,createdAt,lastLogin,isAdmin\n' +
      users.map(u => `"${u.username}","${u.email}","${u.bio || ''}","${u.createdAt}","${u.lastLogin || ''}","${u.isAdmin}"`).join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=users.csv');
    return res.send(csv);
  }
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename=users.json');
  res.send(JSON.stringify(users, null, 2));
});

// IMPORT USERS
// WEEK 5: AJAX import sends x-csrf-token header (see admin dashboard importUsers script)
app.post('/admin/import', (req, res) => {
  if (!req.user || !req.user.isAdmin) {
    return res.redirect('/login');
  }
  // VULNERABILITY: No file validation, no size limits
  let fileData = '';
  req.on('data', chunk => { fileData += chunk; });
  req.on('end', () => {
    try {
      const contentType = req.headers['content-type'];
      let importedUsers = [];
      if (contentType && contentType.includes('multipart/form-data')) {
        // Simple multipart parsing (not robust, but works for demo)
        const boundary = req.headers['content-type'].split('boundary=')[1];
        const parts = fileData.split('--' + boundary);
        for (const part of parts) {
          if (part.includes('filename=')) {
            const content = part.split('\r\n\r\n').slice(1).join('\r\n').trim();
            const text = content.replace(/\r\n/g, '\n').trim();
            if (text.endsWith('.json') || text.includes('{')) {
              try {
                const json = JSON.parse(text.substring(text.indexOf('{')));
                importedUsers = Array.isArray(json) ? json : [json];
              } catch {}
            } else if (text.includes('username,email')) {
              const lines = text.split('\n').slice(1);
              for (const line of lines) {
                const [username, email, bio, createdAt, lastLogin, isAdmin] = line.match(/"([^"]*)"/g)?.map(s => s.slice(1, -1)) || [];
                if (username) {
                  importedUsers.push({ username, email, bio: validator.escape(bio || ''), createdAt: createdAt || new Date().toISOString(), lastLogin: lastLogin || null, isAdmin: isAdmin === 'true', password: 'imported123' });
                }
              }
            }
          }
        }
      }
      if (importedUsers.length === 0) {
        // Fallback: try parsing the body as JSON
        try {
          const json = JSON.parse(fileData);
          importedUsers = Array.isArray(json) ? json : [json];
        } catch {
          // Try CSV
          const lines = fileData.split('\n');
          if (lines[0].includes('username,email')) {
            for (const line of lines.slice(1)) {
              const parts = line.match(/"([^"]*)"/g)?.map(s => s.slice(1, -1));
              if (parts && parts[0]) {
                importedUsers.push({
                  username: parts[0],
                  email: parts[1] || '',
                  bio: validator.escape(parts[2] || ''),
                  createdAt: parts[3] || new Date().toISOString(),
                  lastLogin: parts[4] || null,
                  isAdmin: parts[5] === 'true',
                  password: 'imported123'
                });
              }
            }
          }
        }
      }
      for (const u of importedUsers) {
        if (!u.createdAt) u.createdAt = new Date().toISOString();
        if (!u.password) u.password = 'imported123'; // VULNERABILITY: Default password
        if (!('isAdmin' in u)) u.isAdmin = false;
        if (u.bio) u.bio = validator.escape(u.bio);
        users.push(u);
      }
      saveUsers(users);
      res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Import Successful</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="admin-container" style="margin-top: 80px;">
    <div class="container">
      <div class="card">
        <div class="message success">Imported ${importedUsers.length} user(s) successfully!</div>
        <div class="links">
          <a href="/admin" class="btn btn-primary">Back to Admin Dashboard</a>
        </div>
      </div>
    </div>
  </div>
</body>
</html>`);
    } catch (e) {
      res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Import Failed</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="admin-container" style="margin-top: 80px;">
    <div class="container">
      <div class="card">
        <div class="message error">Import failed: ${e.message}</div>
        <div class="links">
          <a href="/admin" class="btn btn-primary">Back to Admin</a>
        </div>
      </div>
    </div>
  </div>
</body>
</html>`);
    }
  });
});

// RESET ALL USERS
app.get('/admin/reset-all', (req, res) => {
  if (!req.user || !req.user.isAdmin) {
    return res.redirect('/login');
  }
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset All Users</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="admin-container" style="margin-top: 80px;">
    <div class="container">
      <div class="card confirm-card">
        <div class="confirm-warning">🗑️</div>
        <h2>Reset All Users?</h2>
        <p style="color: #a0a0a0; margin: 20px 0;">This will delete ALL ${users.length} user(s) from the system.</p>
        <div class="confirm-details">
          <p><strong>Current users:</strong> ${users.length}</p>
          <p><strong>Admins:</strong> ${users.filter(u => u.isAdmin).length}</p>
        </div>
        <p style="color: #ef4444; font-size: 0.9rem;">This action cannot be undone. All data will be lost.</p>
        <form method="POST" action="/admin/reset-all" style="margin-top: 25px;">
          ${getCsrfField(req)}
          <div class="form-actions">
            <button type="submit" class="btn btn-danger">Yes, Reset All Users</button>
            <a href="/admin" class="btn btn-secondary">Cancel</a>
          </div>
        </form>
      </div>
    </div>
  </div>
</body>
</html>`);
});

app.post('/admin/reset-all', (req, res) => {
  if (!req.user || !req.user.isAdmin) {
    return res.redirect('/login');
  }
  const count = users.length;
  users = [];
  req.user = null;
  res.clearCookie('token');
  saveUsers(users);
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>All Users Reset</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="admin-container" style="margin-top: 80px;">
    <div class="container">
      <div class="card">
        <div class="message success">All ${count} user(s) have been deleted</div>
        <div class="links">
          <a href="/" class="btn btn-primary">Back to Home</a>
          <a href="/register" class="btn btn-secondary">Create First User</a>
        </div>
      </div>
    </div>
  </div>
</body>
</html>`);
});

// WEEK 5: Reject forged requests when CSRF token is missing or invalid
app.use((err, req, res, next) => {
  if (err.code !== 'EBADCSRFTOKEN') {
    return next(err);
  }
  logger.warn('CSRF token validation failed', { path: req.path, ip: req.ip });
  res.status(403).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Forbidden</title>
  <link rel="stylesheet" href="/css/style.css">
</head>
<body>
  ${getNavbar(req.user)}
  <div class="container" style="margin-top: 80px;">
    <div class="card">
      <div class="message error">Invalid or missing CSRF token. This request was blocked to prevent cross-site request forgery.</div>
      <div class="links" style="margin-top: 20px;">
        <a href="/" class="btn btn-primary">Back to Home</a>
      </div>
    </div>
  </div>
</body>
</html>`);
});

app.listen(3000, () => {
  logger.info('Application started on port 3000');
  console.log('App running at http://localhost:3000');
});
