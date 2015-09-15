var defaultToken = require('./DefaultToken');
var ConfigError = require('../errors/ConfigError');
var UnauthorizedError = require('../errors/UnauthorizedError');
var Snowman = require('@hatchpad/node-snowman');
var dot = require('dot-object');
var jwt = require('jwt-simple');
var CONFIG_ERROR = 'ConfigError';

module.exports = function(options) {

  if (!options) {
    throw new ConfigError(CONFIG_ERROR, { message: 'options is required' });
  }

  var roles = options.roles;
  var scopes = options.scopes;
  var secret = options.secret;
  var token = options.token || defaultToken;
  var enforceExp = options.enforceExp === false ? false : true;

  if (roles && !Array.isArray(roles) && typeof(roles) !== 'function') {
    throw new ConfigError(CONFIG_ERROR, { message: 'roles must be an array or a function' });
  }

  if (scopes && !Array.isArray(scopes) && typeof(scopes) !== 'function') {
    throw new ConfigError(CONFIG_ERROR, { message: 'scopes must be an array or a function' });
  }

  if (!secret) {
    throw new ConfigError(CONFIG_ERROR, { message: 'secret is required' });
  }

  if (typeof(secret) !== 'string' && typeof(secret) !== 'function') {
    throw new ConfigError(CONFIG_ERROR, { message: 'secret must be a string or a function' });
  }

  if (typeof(token) !== 'string' && typeof(token) !== 'function') {
    throw new ConfigError(CONFIG_ERROR, { message: 'token must be a string or a function' });
  }

  var setVal = function(key, val, errorCode, errorMessage) {
    if (typeof(val) !== 'function') {
      dot.str('_meta.' + key, val, this.getData());
      this.resolve();
    } else {
      val(this.getData().req, function(err, derivedVal) {
        if (err) {
          if (errorCode) {
            setUnauthorizedError.bind(this)(errorCode, errorMessage);
          }
          this.reject();
        } else {
          dot.str('_meta.' + key, derivedVal, this.getData());
          this.resolve();
        }
      }.bind(this));
    }
  };

  var getSecret = function() {
    setVal.bind(this)('secret', secret);
  };

  var getToken = function() {
    setVal.bind(this)('token', token, 'token_required', 'Token is required');
  };

  var getRoles = function() {
    setVal.bind(this)('roles', roles);
  };

  var getScopes = function() {
    setVal.bind(this)('scopes', scopes);
  };

  var decodeToken = function() {
    var secret = dot.pick('_meta.secret', this.getData());
    var token = dot.pick('_meta.token', this.getData());
    if (!secret || !token) {
      setUnauthorizedError.bind(this)('token_required', 'Token is required in req.headers["x-auth-token"]');
      this.reject();
    } else {
      try {
        var decodedToken = jwt.decode(token, secret);
        var req = dot.pick('req', this.getData());
        dot.str('_meta.decodedToken', decodedToken, this.getData());
        req.user = decodedToken;
        this.resolve();
      } catch (err) {
        setUnauthorizedError.bind(this)('invalid_token', 'Cannot decode auth token');
        this.reject();
      }
    }
  };

  var checkExp = function() {
    var exp = dot.pick('_meta.decodedToken.exp', this.getData());
    if (!exp || !enforceExp) {
      this.resolve();
    } else {
      var now = Date.now();
      if (exp > now) {
        this.resolve();
      } else {
        setUnauthorizedError.bind(this)('token_expired', 'This token has expired');
        this.reject();
      }
    }
  };

  var setUnauthorizedError = function(code, message) {
    var error = new
    dot.str('_meta.unauthorizedError', new UnauthorizedError(code, message), this.getData());
  };

  var sourceArrayContainsOneOfTargetArray = function(sourceArr, targetArr, unauthorizedErrorCode, unauthorizedErrorMessage) {
    if (!targetArr || targetArr.length == 0) {
      this.resolve();
    } else if (!sourceArr) {
      setUnauthorizedError.bind(this)(unauthorizedErrorCode, unauthorizedErrorMessage);
      this.reject();
    } else {
      var contains = false;
      for (var key in sourceArr) {
        if (targetArr.indexOf(sourceArr[key]) >= 0) {
          contains = true;
          break;
        }
      }
      if (contains) {
        this.resolve();
      } else {
        setUnauthorizedError.bind(this)(unauthorizedErrorCode, unauthorizedErrorMessage);
        this.reject();
      }
    }
  };

  var checkRoles = function() {
    var targetRoles = dot.pick('_meta.decodedToken.roles', this.getData());
    var requiredRoles = dot.pick('_meta.roles', this.getData());
    sourceArrayContainsOneOfTargetArray.bind(this)(targetRoles, requiredRoles, 'missing_role', 'This token is missing the required role');
  };

  var checkScopes = function() {
    var targetScopes = dot.pick('_meta.decodedToken.scopes', this.getData());
    var requiredScopes = dot.pick('_meta.scopes', this.getData());
    sourceArrayContainsOneOfTargetArray.bind(this)(targetScopes, requiredScopes, 'missing_scope', 'This token is missing the required scope');
  };

  return function(req, res, next) {
    new Snowman({req:req})
    .$(getSecret)
    .$(getToken)
    .$(decodeToken)
    .$(checkExp)
    .$(getRoles)
    .$(getScopes)
    .$(checkRoles)
    .$(checkScopes)
    .exec(
      function() {
        next();
      },
      function() {
        var error = dot.pick('_meta.unauthorizedError', this.getData());
        next(error);
      }
    );
  };
};