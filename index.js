var fs = require('fs')
var crypto = require('crypto')
var P = require('bluebird')
var inherits = require('util').inherits
var fetch = require('fetch').fetchUrl
var jwk2pem = require('pem-jwk').jwk2pem
var pem2jwk = require('pem-jwk').pem2jwk

var JWT_STRING = /^([a-zA-Z0-9\-_]+)\.([a-zA-Z0-9\-_]+)\.([a-zA-Z0-9\-_]+)$/

function base64url(str) {
  var base64 = Buffer(str).toString('base64')
  return base64.replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

function sign(jwt, pem) {
  var header = base64url(JSON.stringify(jwt.header))
  var payload = base64url(JSON.stringify(jwt.payload))
  var signed = header + '.' + payload
  var s = crypto.createSign('RSA-SHA256')
  s.update(signed)
  var sig = base64url(s.sign(pem))
  return signed + '.' + sig
}

function decode(str) {
  var match = JWT_STRING.exec(str)
  if (!match) {
    return null
  }
  try {
    return {
      header: JSON.parse(Buffer(match[1], 'base64')),
      payload: JSON.parse(Buffer(match[2], 'base64')),
      signature: Buffer(match[3], 'base64')
    }
  }
  catch (e) {
    return null
  }
}

function verify(str, pem) {
  var jwt = decode(str)
  if (!jwt) { return false }
  var signed = str.split('.', 2).join('.')
  var v = crypto.createVerify('RSA-SHA256')
  v.update(signed)
  return v.verify(pem, jwt.signature) ? jwt.payload : false
}

function addExtras(obj, extras) {
  extras = extras || {}
  Object.keys(extras).forEach(
    function (key) {
      obj[key] = extras[key]
    }
  )
  return obj
}

function JWK(jwk, pem) {
  this.jwk = jwk || pem2jwk(pem)
  this.pem = pem || jwk2pem(jwk)
}

JWK.fromPEM = function (pem, extras) {
  var obj = pem2jwk(pem, extras)
  if (obj.d) {
    return new PrivateJWK(obj, pem)
  }
  return new PublicJWK(obj, pem)
}

JWK.fromObject = function (obj, extras) {
  obj = addExtras(obj, extras)
  if (obj.d) {
    return new PrivateJWK(obj)
  }
  return new PublicJWK(obj)
}

JWK.fromFile = function (filename, extras) {
  var file = fs.readFileSync(filename, 'utf8')
  if (file[0] === '{') {
    return JWK.fromObject(JSON.parse(file), extras)
  }
  return JWK.fromPEM(file, extras)
}

JWK.prototype.toJSON = function () {
  return this.jwk
}

function PrivateJWK(jwk, pem) {
  JWK.call(this, jwk, pem)
}
inherits(PrivateJWK, JWK)

PrivateJWK.prototype.signSync = function (data) {
  var payload = data || {}
  payload.iss = this.jwk.iss
  return sign(
    {
      header: {
        alg: 'RS256',
        jku: this.jwk.jku,
        kid: this.jwk.kid
      },
      payload: payload
    },
    this.pem
  )
}

PrivateJWK.prototype.sign = function (data) {
  return P.resolve(this.signSync(data))
}

function PublicJWK(jwk, pem) {
  JWK.call(this, jwk, pem)
}
inherits(PublicJWK, JWK)

PublicJWK.prototype.verifySync = function (str) {
  return verify(str, this.pem)
}

PublicJWK.prototype.verify = function (str) {
  return P.resolve(this.verifySync(str))
}

function JWTVerificationError(msg) {
  this.name = 'JWTVerificationError'
  this.message = msg
}
inherits(JWTVerificationError, Error)

function JWTool(trusted) {
  this.trusted = trusted
  this.jwkSets = {}
}
JWTool.BN = require('pem-jwk').BN
JWTool.JWK = JWK
JWTool.PublicJWK = PublicJWK
JWTool.PrivateJWK = PrivateJWK
JWTool.JWTVerificationError = JWTVerificationError
JWTool.unverify = decode
JWTool.verify = verify
JWTool.sign = sign

function getJwkSet(jku) {
  var d = P.defer()
  fetch(
    jku,
    {
      disableRedirects: true,
      rejectUnauthorized: true
    },
    function (err, res, body) {
      if (err) { return d.reject(err) }
      try {
        var json = JSON.parse(body)
        var set = {}
        json.keys.forEach(
          function (key) {
            set[key.kid] = new PublicJWK(key)
          }
        )
        d.resolve(set)
      }
      catch (e) {
        return d.reject(new JWTVerificationError('bad jku'))
      }
    }
  )
  return d.promise
}


JWTool.prototype.fetch = function (jku, kid) {
  var set = this.jwkSets[jku]
  if (set && set[kid]) {
    return P.resolve(set[kid])
  }
  return getJwkSet(jku)
    .then(
      function (set) {
        this.jwkSets[jku] = set
        if (!set[kid]) {
          return P.reject(new JWTVerificationError('unknown kid'))
        }
        return P.resolve(set[kid])
      }.bind(this)
    )
}

JWTool.prototype.verify = function (str) {
  var jwt = decode(str)
  if (!jwt) { return P.reject(new JWTVerificationError('malformed')) }
  if (this.trusted.indexOf(jwt.header.jku) === -1) {
    return P.reject(new JWTVerificationError('untrusted'))
  }
  return this.fetch(jwt.header.jku, jwt.header.kid)
    .then(
      function (jwk) {
        return jwk.verify(str)
      }
    )
    .then(
      function (jwt) {
        if (!jwt) { return P.reject(new JWTVerificationError('invalid')) }
        return P.resolve(jwt)
      }
    )
}

module.exports = JWTool
