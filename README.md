# User Management App

A simple web-based user management system built with Node.js and Express.

## Features

- User registration and login
- Password hashing with bcrypt
- JWT-based session management
- User profile management
- Admin dashboard for user administration
- XSS protection via input sanitization
- Security headers with Helmet

## Tech Stack

- **Backend:** Node.js, Express.js
- **Authentication:** bcrypt, jsonwebtoken
- **Security:** Helmet
- **Templating:** EJS
- **Validation:** validator.js
- **Logging:** Winston

## Installation

1. Clone the repository:
   ```bash
   git clone (https://github.com/danish-gulzar/user-management-app/tree/main)
   cd user-management-app-v1
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environment variables:
   ```bash
   cp .env.example .env
   ```

4. Edit `.env` and set your JWT secret:
   ```
   JWT_SECRET=your-secure-random-string
   ```

   To generate a secure secret:
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

5. Start the server:
   ```bash
   node app.js
   ```

6. Open your browser and navigate to:
   ```
   http://localhost:3000
   ```

## Usage

### First User
The first user registered automatically becomes an admin.

### Admin Features
- View all users
- Add new users
- Edit user details
- Delete users
- Export users (JSON/CSV)
- Import users from file

### Regular User Features
- View and edit profile
- Change password
- Access personal dashboard

## Project Structure

```
user-management-app-v1/
├── app.js              # Main application file
├── package.json        # Dependencies
├── .env                # Environment variables (not committed)
├── .env.example        # Environment template
├── .gitignore          # Git ignore rules
├── users.json          # User data storage
├── security.log        # Security logs
├── public/
│   └── css/
│       └── style.css   # Styles
└── README.md           # This file
```

## Security Notes

- Passwords are hashed using bcrypt before storage
- JWT tokens expire after 1 hour
- Input validation and sanitization to prevent XSS
- Security headers via Helmet middleware
- Never commit `.env` or `users.json` to version control

## License

ISC
#
