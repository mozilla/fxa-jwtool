var fs = require('fs')
var assert = require('assert')
var JWTool = require('../index')

var secretKey = fs.readFileSync(__dirname + '/priv.pem', 'utf8')
var publicKey = fs.readFileSync(__dirname + '/pub.pem', 'utf8')

var str = JWTool.sign({ header: { foo: 'x' }, payload: { bar: 'baz' } }, secretKey)
console.log(str)
var jwt = JWTool.verify(str, publicKey)
console.log(jwt)
