module.exports = function(req, callback) {
  var token = req.headers['x-auth-token'] ||
    req.headers['x-auth'] ||
    req.headers['auth-token'];
  callback(!token, token);
};
