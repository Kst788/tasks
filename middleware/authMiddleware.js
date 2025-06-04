const jwt = require('jsonwebtoken');

const authenticate = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.redirect('/auth/login');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // ✅ attach decoded payload to req.user
    next();
  } catch (err) {
    console.error('JWT Error:', err.message);
    res.clearCookie('token');
    return res.redirect('/auth/login');
  }
};

module.exports = authenticate;
