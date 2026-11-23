/**
 * Remediation Fix: Robust Access Control & IDOR Prevention
 * Targets: SEC-03 (Insecure Direct Object Reference) & SEC-04 (Broken Function-Level Access Control)
 * Tech Stack: Node.js, Express, JWT
 */

const jwt = require('jsonwebtoken');
const { BasketModel, BasketItemModel } = require('../models');

// 1. JWT Authentication & Context Verification Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied: Authentication token required.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decodedUser) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired session token.' });
    }
    req.user = decodedUser; // req.user contains { sub: userId, role: userRole, bid: basketId }
    next();
  });
}

// 2. Strict Role-Based Access Control (RBAC) Middleware (Mitigates SEC-04)
function requireRole(allowedRole) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== allowedRole) {
      return res.status(403).json({
        error: 'Forbidden: Insufficient privileges to access this resource.'
      });
    }
    next();
  };
}

// -------------------------------------------------------------
// VULNERABLE IMPLEMENTATION (Root Cause SEC-03):
// -------------------------------------------------------------
// exports.vulnerableGetBasket = (req, res) => {
//   // VULNERABILITY: Blindly trusts client-supplied URL parameter without owner check
//   const basketId = req.params.id;
//   models.Basket.findOne({ where: { id: basketId } })
//     .then(basket => res.json(basket));
// };

// -------------------------------------------------------------
// SECURE REMEDIATION IMPLEMENTATION (Fix for SEC-03):
// -------------------------------------------------------------
async function secureGetBasket(req, res) {
  try {
    const requestedBasketId = parseInt(req.params.id, 10);

    // FIX: Enforce Object-Level Ownership Check (Mitigates IDOR / BOLA)
    // Non-admin users can ONLY query the basket ID bound to their authenticated token
    if (req.user.role !== 'admin' && req.user.bid !== requestedBasketId) {
      return res.status(403).json({
        error: 'Forbidden: You do not have permission to view or modify this basket.'
      });
    }

    const basket = await BasketModel.findOne({
      where: { id: requestedBasketId },
      include: [{ model: BasketItemModel }]
    });

    if (!basket) {
      return res.status(404).json({ error: 'Basket not found.' });
    }

    return res.status(200).json({ status: 'success', data: basket });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to retrieve basket data.' });
  }
}

module.exports = {
  authenticateToken,
  requireRole,
  secureGetBasket
};
