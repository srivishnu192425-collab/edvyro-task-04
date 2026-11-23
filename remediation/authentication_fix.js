/**
 * Remediation Fix: Secure Authentication & Rate Limiting
 * Targets: SEC-01 (SQL Injection Auth Bypass) & SEC-02 (Weak Password / Brute Force)
 * Tech Stack: Node.js, Express, Sequelize ORM, express-rate-limit, bcrypt
 */

const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { UserModel } = require('../models');

// 1. Enforce strict rate limiting on authentication routes (Mitigates SEC-02)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15-minute window
  max: 5, // Limit each IP to 5 failed login attempts per window
  message: {
    status: 429,
    message: 'Too many login attempts from this IP. Please try again after 15 minutes.'
  },
  standardHeaders: true,
  legacyHeaders: false
});

// 2. Strong Password Policy Validator (Mitigates SEC-02)
function validatePasswordStrength(password) {
  // Requires: Minimum 12 characters, at least 1 uppercase, 1 lowercase, 1 number, and 1 special char
  const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;
  return strongPasswordRegex.test(password);
}

// -------------------------------------------------------------
// VULNERABLE IMPLEMENTATION (Root Cause SEC-01):
// -------------------------------------------------------------
// exports.vulnerableLogin = async (req, res) => {
//   // VULNERABILITY: Raw string concatenation directly inside SQL query
//   const rawQuery = `SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${security.hash(req.body.password)}' AND deletedAt IS NULL`;
//   models.sequelize.query(rawQuery, { model: models.User, plain: true })
//     .then(user => { /* issues JWT */ });
// };

// -------------------------------------------------------------
// SECURE REMEDIATION IMPLEMENTATION (Fix for SEC-01):
// -------------------------------------------------------------
async function secureLogin(req, res) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    // FIX: Parameterized query via Sequelize ORM abstraction (prevents SQL injection)
    const user = await UserModel.findOne({
      where: {
        email: email.trim().toLowerCase(),
        deletedAt: null
      }
    });

    if (!user) {
      // Return generic error message to prevent user enumeration
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // FIX: Constant-time secure password hash comparison using bcrypt
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Generate secure scoped JWT token
    const token = jwt.sign(
      {
        sub: user.id,
        email: user.email,
        role: user.role,
        bid: user.basketId
      },
      process.env.JWT_SECRET,
      { expiresIn: '2h', algorithm: 'HS256' }
    );

    return res.status(200).json({
      status: 'success',
      data: {
        token,
        bid: user.basketId
      }
    });
  } catch (err) {
    return res.status(500).json({ error: 'Internal authentication error.' });
  }
}

module.exports = {
  authLimiter,
  validatePasswordStrength,
  secureLogin
};
