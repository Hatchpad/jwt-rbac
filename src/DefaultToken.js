module.exports = function(req, callback) {
  const token = req.headers['x-auth-token'] ||
    req.headers['Authorization'] ||
    req.headers['x-auth'] ||
    req.headers['auth-token'];
  if (!!token && token.substr(0, 7) === 'Bearer ') {
    callback(!token, token.substring(7, token.length));
  }
  callback(!token, token);
};
