const defaultToken = require('./DefaultToken');
const ConfigError = require('../errors/ConfigError');
const UnauthorizedError = require('../errors/UnauthorizedError');
const Snowman = require('node-snowman');
const dot = require('dot-object');
const jwt = require('jwt-simple');
const CONFIG_ERROR = 'ConfigError';

module.exports = function(options) {

  if (!options) {
    throw new ConfigError(CONFIG_ERROR, { message: 'options is required' });
  }

  let roles = options.roles;
  let scopes = options.scopes;
  let secret = options.secret;
  let token = options.token || defaultToken;
  let enforceExp = options.enforceExp === undefined ||
    options.enforceExp === null ||
    options.enforceExp === true ? true : options.enforceExp || false;
  let authRequired = options.authRequired === false ? false : true;
  let privilege = options.privilege;
  let revoked = options.revoked;

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

  if (privilege && typeof(privilege) !== 'function') {
    throw new ConfigError(CONFIG_ERROR, { message: 'privilege must be a function' });
  }

  if (revoked && typeof(revoked) !== 'function') {
    throw new ConfigError(CONFIG_ERROR, { message: 'revoked must be a function' });
  }

  if (typeof(enforceExp) !== 'function' && typeof(enforceExp) !== 'boolean') {
    throw new ConfigError(CONFIG_ERROR, { message: 'enforceExp must be a boolean or a function' });
  }

  const setVal = function(key, val, errorCode, errorMessage) {
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

  const getSecret = function() {
    setVal.bind(this)('secret', secret);
  };

  const getToken = function() {
    setVal.bind(this)('token', token, 'token_required', 'Token is required');
  };

  const getRoles = function() {
    setVal.bind(this)('roles', roles);
  };

  const getScopes = function() {
    setVal.bind(this)('scopes', scopes);
  };

  const decodeToken = function() {
    const secret = dot.pick('_meta.secret', this.getData());
    const token = dot.pick('_meta.token', this.getData());
    if (!secret || !token) {
      setUnauthorizedError.bind(this)('token_required', 'Token is required in req.headers["x-auth-token"]');
      this.reject();
    } else {
      let resolve = true;
      try {
        const decodedToken = jwt.decode(token, secret);
        const req = dot.pick('req', this.getData());
        dot.str('_meta.decodedToken', decodedToken, this.getData());
        req.user = decodedToken;
      } catch (err) {
        setUnauthorizedError.bind(this)('invalid_token', 'Cannot decode auth token');
        resolve = false;
      }
      if (resolve) {
        this.resolve();
      } else {
        this.reject();
      }
    }
  };

  const checkExp = function() {
    const exp = dot.pick('_meta.decodedToken.exp', this.getData());

    const checkIt = function() {
      const now = Date.now();
      if (exp > now) {
        this.resolve();
      } else {
        setUnauthorizedError.bind(this)('token_expired', 'This token has expired');
        this.reject();
      }
    };

    if (!exp || !enforceExp) {
      this.resolve();
    } else if (enforceExp === true) {
      checkIt.bind(this)();
    } else {
      enforceExp(this.getData().req, this.getData()._meta.decodedToken, function(enforceIt) {
        if (!enforceIt) {
          this.resolve();
        } else {
          checkIt.bind(this)();
        }
      }.bind(this));
    }
  };

  const checkPrivilege = function() {
    if (!privilege) {
      this.resolve();
    } else {
      privilege(this.getData().req, this.getData()._meta.decodedToken, function(hasPriv) {
        if (hasPriv) {
          this.resolve();
        } else {
          setUnauthorizedError.bind(this)('missing_privilege', 'This token lacks the required privilege');
          this.reject();
        }
      }.bind(this));
    }
  };

  const checkRevoked = function() {
    if (!revoked) {
      this.resolve();
    } else {
      revoked(this.getData().req, this.getData()._meta.decodedToken, function(isRevoked) {
        if (isRevoked) {
          setUnauthorizedError.bind(this)('token_revoked', 'This token has been revoked');
          this.reject();
        } else {
          this.resolve();
        }
      }.bind(this));
    }
  };

  const setUnauthorizedError = function(code, message) {
    dot.str('_meta.unauthorizedError', new UnauthorizedError(code, message), this.getData());
  };

  const sourceArrayContainsOneOfTargetArray = function(sourceArr, targetArr, unauthorizedErrorCode, unauthorizedErrorMessage) {
    if (!targetArr || targetArr.length == 0) {
      this.resolve();
    } else if (!sourceArr) {
      setUnauthorizedError.bind(this)(unauthorizedErrorCode, unauthorizedErrorMessage);
      this.reject();
    } else {
      let contains = false;
      for (let key in sourceArr) {
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

  const checkRoles = function() {
    const targetRoles = dot.pick('_meta.decodedToken.roles', this.getData());
    const requiredRoles = dot.pick('_meta.roles', this.getData());
    sourceArrayContainsOneOfTargetArray.bind(this)(targetRoles, requiredRoles, 'missing_role', 'This token is missing the required role');
  };

  const checkScopes = function() {
    const targetScopes = dot.pick('_meta.decodedToken.scopes', this.getData());
    const requiredScopes = dot.pick('_meta.scopes', this.getData());
    sourceArrayContainsOneOfTargetArray.bind(this)(targetScopes, requiredScopes, 'missing_scope', 'This token is missing the required scope');
  };

  return function(req, res, next) {
    new Snowman({req:req})
    .$(getSecret)
    .$(getToken)
    .$(decodeToken)
    .$(checkRevoked)
    .$(getRoles)
    .$(getScopes)
    .$(checkRoles)
    .$(checkScopes)
    .$(checkExp)
    .$(checkPrivilege)
    .exec(
      function() {
        next();
      },
      function() {
        const error = dot.pick('_meta.unauthorizedError', this.getData());
        if (!authRequired && error.code === 'token_revoked') {
          next(error);
        } else if (!authRequired && error.code === 'token_required') {
          next();
        } else {
          next(error);
        }
      }
    );
  };
};
