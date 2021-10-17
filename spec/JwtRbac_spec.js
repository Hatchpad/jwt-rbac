const rbac = require('../.');
const ConfigError = require('../errors/ConfigError');
const jwt = require('jwt-simple');

const UNAUTHORIZED_ERROR = 'UnauthorizedError';

const aFunc = function() {};
let error;

const next = function(err) {
  error = err;
};

describe('options and default params', function() {
  it('should throw an error if options is undefined', function () {
    expect( function() { rbac();} ).toThrow(new Error('options is required'));
  });

  it('should throw an error if roles is not an array or a function', function() {
    expect( function() { rbac({roles:4});} ).toThrow(new Error('roles must be an array or a function'));
  });

  it('should not throw an error if roles is an array', function() {
    expect( function() { rbac({roles:['general', 'admin']});} ).not.toThrow(new Error('roles must be an array or a function'));
  });

  it('should not throw an error if roles is a function', function() {
    expect( function() { rbac({roles:aFunc});} ).not.toThrow(new Error('roles must be an array or a function'));
  });

  it('should throw an error if scopes is not an array or a function', function() {
    expect( function() { rbac({scopes:4});} ).toThrow(new Error('scopes must be an array or a function'));
  });

  it('should not throw an error if scopes is an array', function() {
    expect( function() { rbac({scopes:['general', 'admin']});} ).not.toThrow(new Error('scopes must be an array or a function'));
  });

  it('should not throw an error if scopes is a function', function() {
    expect( function() { rbac({scopes:aFunc});} ).not.toThrow(new Error('scopes must be an array or a function'));
  });

  it('should throw an error if secret is undefined', function () {
    expect( function() { rbac({roles:[]});} ).toThrow(new Error('secret is required'));
  });

  it('should throw an error if secret is not a string or a function', function() {
    expect( function() { rbac({scopes:[], secret:4});} ).toThrow(new Error('secret must be a string or a function'));
  });

  it('should not throw an error if secret is a string', function() {
    expect( function() { rbac({scopes:[], secret:'str'});} ).not.toThrow(new Error('secret must be a string or a function'));
  });

  it('should not throw an error if secret is a function', function() {
    expect( function() { rbac({scopes:[], secret:aFunc});} ).not.toThrow(new Error('secret must be a string or a function'));
  });

  it('should throw an error if token is not a string or a function', function() {
    expect( function() { rbac({scopes:[], secret:'sec', token:4});} ).toThrow(new Error('token must be a string or a function'));
  });

  it('should not throw an error if token is a string', function() {
    expect( function() { rbac({scopes:[], secret:'sec', token:'str'});} ).not.toThrow(new Error('token must be a string or a function'));
  });

  it('should not throw an error if token is a function', function() {
    expect( function() { rbac({scopes:[], secret:'sec', token:aFunc});} ).not.toThrow(new Error('token must be a string or a function'));
  });

  it('should throw an error if enforceExp is not a function or boolean', function() {
    expect( function() { rbac({scopes:[], secret:'sec', enforceExp:4});} ).toThrow(new Error('enforceExp must be a boolean or a function'));
  });

  it('should not throw an error if enforceExp is true', function() {
    expect( function() { rbac({scopes:[], secret:'sec', enforceExp:aFunc});} ).not.toThrow(new Error('enforceExp must be a boolean or a function'));
  });
});

describe('functional', function() {
  const staticSecret = 'SEC';

  const createToken = function(obj, secret) {
    return jwt.encode(obj, secret);
  };

  describe('very basic roles', function() {
    let rbacFunc, token, req;

    beforeEach(function() {
      error = null;
      token = createToken({roles:['general', 'admin']}, staticSecret);
      req = {headers: {'x-auth-token': token}};
    });

    it('authorizes correctly', function() {
      rbacFunc = rbac({roles:['general'], secret:staticSecret});
      rbacFunc(req, null, next);
      expect(error).toBe(undefined);
    });

    it('authorizes correctly', function() {
      rbacFunc = rbac({roles:['admin'], secret:staticSecret});
      rbacFunc(req, null, next);
      expect(error).toBe(undefined);
    });

    it('unauthorizes correctly', function() {
      rbacFunc = rbac({roles:['finance'], secret:staticSecret});
      rbacFunc(req, null, next);
      expect(error.name).toBe(UNAUTHORIZED_ERROR);
      expect(error.code).toBe('missing_role');
      expect(error.message).toBe('This token is missing the required role');
    });
  });

  describe('bearer token', function() {
    let rbacFunc, token, req;

    beforeEach(function () {
      error = null;
      token = createToken({roles: ['general', 'admin']}, staticSecret);
      req = {headers: {'Authorization': `Bearer ${token}`}};
    });

    it('authorizes correctly', function () {
      rbacFunc = rbac({roles: ['general'], secret: staticSecret});
      rbacFunc(req, null, next);
      expect(error).toBe(undefined);
    });
  });

  describe('very basic scopes', function() {
    let rbacFunc, token, req;

    beforeEach(function() {
      error = null;
      token = createToken({scopes:['confirm-email']}, staticSecret);
      req = {headers: {'x-auth-token': token}};
    });

    it('authorizes correctly', function() {
      rbacFunc = rbac({scopes:['confirm-email'], secret:staticSecret});
      rbacFunc(req, null, next);
      expect(error).toBe(undefined);
    });

    it('unauthorizes correctly', function() {
      rbacFunc = rbac({scopes:['auth'], secret:staticSecret});
      rbacFunc(req, null, next);
      expect(error.name).toBe(UNAUTHORIZED_ERROR);
      expect(error.code).toBe('missing_scope');
      expect(error.message).toBe('This token is missing the required scope');
    });
  });

  describe('exp', function() {
    let rbacFunc, token, req;

    describe('not expired', function() {
      beforeEach(function() {
        error = null;
        var now = Date.now();
        token = createToken({exp: now + 5000}, staticSecret);
        req = {headers: {'x-auth-token': token}};
      });

      it('authorizes', function() {
        rbacFunc = rbac({secret:staticSecret});
        rbacFunc(req, null, next);
        expect(error).toBe(undefined);
      });
    });

    describe('expired', function() {
      beforeEach(function(done) {
        error = null;
        const now = Date.now();
        token = createToken({exp: now}, staticSecret);
        req = {headers: {'x-auth-token': token}};
        setTimeout(function() {
          done();
        }, 10);
      });

      it('unauthorizes', function() {
        rbacFunc = rbac({secret:staticSecret});
        rbacFunc(req, null, next);
        expect(error.name).toBe(UNAUTHORIZED_ERROR);
        expect(error.code).toBe('token_expired');
        expect(error.message).toBe('This token has expired');
      });

      it('unauthorizes with function', function() {
        const func = function(req, token, cb) {
          cb(true);
        };
        rbacFunc = rbac({secret:staticSecret});
        rbacFunc(req, null, next);
        expect(error.name).toBe(UNAUTHORIZED_ERROR);
        expect(error.code).toBe('token_expired');
        expect(error.message).toBe('This token has expired');
      });
    });

    describe('expired but not enforced', function() {
      beforeEach(function(done) {
        error = null;
        const now = Date.now();
        token = createToken({exp: now}, staticSecret);
        req = {headers: {'x-auth-token': token}};
        setTimeout(function() {
          done();
        }, 10);
      });

      it('authorizes', function() {
        rbacFunc = rbac({secret:staticSecret, enforceExp:false});
        rbacFunc(req, null, next);
        expect(error).toBe(undefined);
      });

      it('authorizes with function', function() {
        const func = function(req, token, cb) {
          cb(false);
        };
        rbacFunc = rbac({secret:staticSecret, enforceExp:func});
        rbacFunc(req, null, next);
        expect(error).toBe(undefined);
      });
    });
  });

  describe('token issues', function() {
    let rbacFunc, token, req;

    describe('required', function() {
      beforeEach(function() {
        error = null;
        req = {headers:{}};
      });

      it('unauthorizes', function() {
        rbacFunc = rbac({secret:staticSecret});
        rbacFunc(req, null, next);
        expect(error.name).toBe(UNAUTHORIZED_ERROR);
        expect(error.code).toBe('token_required');
        expect(error.message).toBe('Token is required');
      });
    });

    describe('required when authRequired is false', function() {
      beforeEach(function() {
        error = null;
        req = {headers:{}};
      });

      it('authorizes', function() {
        rbacFunc = rbac({secret:staticSecret, authRequired:false});
        rbacFunc(req, null, next);
        expect(error).toBe(undefined);
      });
    });

    describe('invalid', function() {
      beforeEach(function() {
        error = null;
        req = {headers:{'x-auth-token':'whatever'}};
      });

      it('unauthorizes', function() {
        rbacFunc = rbac({secret:staticSecret});
        rbacFunc(req, null, next);
        expect(error.name).toBe(UNAUTHORIZED_ERROR);
        expect(error.code).toBe('invalid_token');
        expect(error.message).toBe('Cannot decode auth token');
      });
    });
  });

  describe('privileges', function() {
    let rbacFunc, privilegeFunc, token, req;

    beforeEach(function() {
      error = null;
      token = createToken({any:'thing'}, staticSecret);
      req = {headers: {'x-auth-token': token}};
    });

    it('authorizes correctly', function() {
      privilegeFunc = function(req, token, cb) {
        cb(true);
      };
      rbacFunc = rbac({privilege: privilegeFunc, secret:staticSecret});
      rbacFunc(req, null, next);
      expect(error).toBe(undefined);
    });

    it('unauthorizes correctly', function() {
      privilegeFunc = function(req, token, cb) {
        cb(false);
      };
      rbacFunc = rbac({privilege: privilegeFunc, secret:staticSecret});
      rbacFunc(req, null, next);
      expect(error.name).toBe(UNAUTHORIZED_ERROR);
      expect(error.code).toBe('missing_privilege');
      expect(error.message).toBe('This token lacks the required privilege');
    });
  });

  describe('revoked', function() {
    let rbacFunc, token, req;

    beforeEach(function() {
      error = null;
      token = createToken({any:'thing'}, staticSecret);
      req = {headers: {'x-auth-token': token}};
    });

    it('authorizes correctly', function() {
      revokedFunc = function(req, token, cb) {
        cb(false);
      };
      rbacFunc = rbac({revoked: revokedFunc, secret:staticSecret});
      rbacFunc(req, null, next);
      expect(error).toBe(undefined);
    });

    it('unauthorizes correctly', function() {
      revokedFunc = function(req, token, cb) {
        cb(true);
      };
      rbacFunc = rbac({revoked: revokedFunc, secret:staticSecret});
      rbacFunc(req, null, next);
      expect(error.name).toBe(UNAUTHORIZED_ERROR);
      expect(error.code).toBe('token_revoked');
      expect(error.message).toBe('This token has been revoked');
    });
  });

  describe('smoke tests with functions', function() {
    let rbacFunc, token, req, rolesFunc1, rolesFunc2;

    beforeEach(function() {
      rolesFunc1 = function(req, cb) {
        cb(false, ['admin']);
      };
      rolesFunc2 = function(req, cb) {
        cb(false, ['finance']);
      };
      error = null;
      token = createToken({roles:['general', 'admin']}, staticSecret);
      req = {headers: {'x-auth-token': token}};
    });

    it('authorizes correctly', function() {
      rbacFunc = rbac({roles:rolesFunc1, secret:staticSecret});
      rbacFunc(req, null, next);
      expect(error).toBe(undefined);
    });

    it('unauthorizes correctly', function() {
      rbacFunc = rbac({roles:rolesFunc2, secret:staticSecret});
      rbacFunc(req, null, next);
      expect(error.name).toBe(UNAUTHORIZED_ERROR);
      expect(error.code).toBe('missing_role');
      expect(error.message).toBe('This token is missing the required role');
    });
  });
});
