function ConfigError (code, error) {
  Error.call(this, error.message);
  Error.captureStackTrace(this, this.constructor);
  this.name = "ConfigError";
  this.message = error.message;
  this.code = code;
  this.status = 401;
  this.inner = error;
}

ConfigError.prototype = Object.create(Error.prototype);
ConfigError.prototype.constructor = ConfigError;

module.exports = ConfigError;
