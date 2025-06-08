// Helper function to get base URL
const getBaseUrl = (req) => {
  // If BASE_URL is set in environment variables, use it
  if (process.env.BASE_URL) {
    return process.env.BASE_URL.replace(/\/$/, '');
  }
  // For production, force HTTPS
  if (process.env.NODE_ENV === 'production') {
    return `https://${req.get('host')}`;
  }
  // For development
  return `${req.protocol}://${req.get('host')}`;
};

module.exports = {
  getBaseUrl
}; 