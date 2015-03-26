# fxa-jwtool

A module for creating and verifying JWTs used by Firefox Accounts.

## Example

```js
var JWTool = require('fxa-jwtool')

var secretKey = JWTool.JWK.fromFile(
  'priv.pem',
  {
    jku: 'https://api.accounts.firefox.com/.well-known/public-keys',
    kid: 'dev-1'
  }
)

var encodedJWT = secretKey.sign({ sub: 'hello world' })

var trustedJKUs = [
  'https://api.accounts.firefox.com/.well-known/public-keys'
]

var jwtool = new JWTool(trustedJKUs)

var message = jwtool.verify(encodedJWT)

console.log(message) // { sub: "hello world" }

```
