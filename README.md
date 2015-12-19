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

Most of the options can take a static value or an asynchronous function. Describing you options as function can be useful because it gives you access to the request and the token so you can determine the value.  For example a user might need to have the "admin" role or perhaps an entity might "belong" to the user so you would be able to fetch it from the database and determine the user associated with it.

These are the valid options:

#### roles (optional)
* can be an array of Strings representing valid roles
* can also be a function like this:
```
function(req, token, callback) {
  var error = false;
  var validRoles = ['admin', 'hr'];
  callback(error, validRoles);
}
```
