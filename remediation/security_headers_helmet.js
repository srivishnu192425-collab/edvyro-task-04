/**
 * Remediation Fix: Defensive Security Headers & Server Hardening
 * Target: SEC-07 (Security Misconfiguration & Missing Headers)
 * Tech Stack: Node.js, Express, Helmet.js
 */

const express = require('express');
const helmet = require('helmet');

const app = express();

// 1. Remove Express identification banner to prevent reconnaissance / version fingerprinting
app.disable('x-powered-by');

// 2. Comprehensive Security Headers with Helmet
app.use(
  helmet({
    // Content-Security-Policy (CSP): Restricts origins for scripts, styles, fonts, frames
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline styles only where necessary
        imgSrc: ["'self'", 'data:', 'https:'],
        fontSrc: ["'self'", 'https:', 'data:'],
        objectSrc: ["'none'"], // Disallows legacy Flash / Java applet injection
        frameAncestors: ["'none'"], // Modern CSP Clickjacking mitigation (replaces X-Frame-Options)
        upgradeInsecureRequests: [] // Instructs browsers to upgrade HTTP to HTTPS
      }
    },

    // X-Frame-Options: Clickjacking defense for legacy browsers
    frameguard: {
      action: 'deny'
    },

    // HTTP Strict Transport Security (HSTS): Enforce HTTPS connections
    hsts: {
      maxAge: 31536000, // 1 year in seconds
      includeSubDomains: true,
      preload: true
    },

    // X-Content-Type-Options: Prevent MIME-sniffing
    noSniff: true,

    // Referrer-Policy: Protect sensitive path/query parameters from leaking to external domains
    referrerPolicy: {
      policy: 'strict-origin-when-cross-origin'
    },

    // Cross-Origin Resource Policy & Embedder Policy
    crossOriginEmbedderPolicy: false, // Adjusted depending on SPA requirements
    crossOriginResourcePolicy: { policy: 'same-origin' }
  })
);

// 3. Permissions-Policy / Feature-Policy: Disable unneeded browser APIs
app.use((req, res, next) => {
  res.setHeader(
    'Permissions-Policy',
    'geolocation=(), camera=(), microphone=(), payment=()'
  );
  next();
});

module.exports = app;
