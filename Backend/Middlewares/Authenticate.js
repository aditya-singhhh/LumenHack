const jwt = require('jsonwebtoken');
const User = require('../Models/User');

// Hardcoded JWT Secret Key (replace with your secret key)
const JWT_SECRET = '123'; // Change this to a secure secret key

const Authenticate = async (req, res, next) => {
  // Retrieve the token from the cookie
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    // Verify the token using the hardcoded JWT_SECRET
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log(decoded);

    // Find the user based on the decoded userId
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    // Attach user data to the request object
    req.user = user;
    req.userId = user._id;  // Add userId to the request for use in the route
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

module.exports = Authenticate;
