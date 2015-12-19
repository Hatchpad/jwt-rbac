# jwt-rbac

JSON Web Token (JWT) role based access control (RBAC) express middleware.

## Installation

`npm install @hatchpad/jwt-rbac --save`

## Usage

### Include

`var JwtRbac = require('@hatchpad/jwt-rbac')`

### Examples

#### Very Basic Authentication
This example assumes there will be a jwt-token in one of the specified locations like "x-auth-token" in the request headers. You can also provide your own function for extracting the token.

It ensures the token will have a roles property with 'admin' as one of the elements
```
var express = require('express');
var router = express.Router();

var canEdit = JwtRbac({
  secret:'jwt-secret',
  roles: ['admin']
});

router.put('/api/users/:id', canEdit, function(req, res, next) {
  post(req, res);
});
```
