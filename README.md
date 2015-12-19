# jwt-rbac

JSON Web Token (JWT) role based access control (RBAC) express middleware.

## Installation

`npm install @hatchpad/jwt-rbac --save`

## Usage

### Include

`var JwtRbac = require('@hatchpad/jwt-rbac');`

### Examples

#### Very Basic Authentication
This example assumes there will be a jwt-token in one of the specified locations like "x-auth-token" in the request headers. You can also provide your own function for extracting the token.

It ensures the token will have a roles property with 'admin' as one of the elements
```
var express = require('express');
var router = express.Router();
var JwtRbac = require('@hatchpad/jwt-rbac');

var canEdit = JwtRbac({
  secret:'jwt-secret',
  roles: ['admin']
});

router.put('/api/users/:id', canEdit, function(req, res, next) {
  post(req, res);
});
```

### options

A JWT-RBAC middleware function is created by passing JwtRbac an object with options like so:

`var rbac = JwtRbac(options);`

These are the valid options:

#### roles
* can be an array of Strings representing valid roles
* can also be a function like this:
```
function(req, token, callback) {
  var error = false;
  var validRoles = ['admin', 'hr'];
  callback(error, validRoles);
}
```
