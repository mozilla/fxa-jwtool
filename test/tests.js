var fs = require('fs')
var http = require('http')
var assert = require('assert')
var JWTool = require('../index')

var secretKey = fs.readFileSync(__dirname + '/priv.pem', 'utf8')
var publicKey = fs.readFileSync(__dirname + '/pub.pem', 'utf8')
var publicJWK = JWTool.JWK.fromPEM(publicKey, {
  kid: 'test1'
})

var server = http.createServer(
  function (req, res) {
    res.writeHead(200, {'Content-Type': 'application/json'})
    res.end(JSON.stringify({ keys: [publicJWK] }))
  }
)
server.once('listening', go)
server.listen(0, '127.0.0.1')

function go() {
  var trustedJKUs = ["http://127.0.0.1:" + server.address().port + '/']

  var secretJWK = JWTool.JWK.fromPEM(secretKey, {
    jku: trustedJKUs[0],
    kid: 'test1'
  })

  var jwtool = new JWTool(trustedJKUs)

  var msg = { bar: 'baz' }

  var str = JWTool.sign({ header: { foo: 'x' }, payload: msg }, secretKey)
  var jwt = JWTool.verify(str, publicKey)
  assert.deepEqual(jwt, msg)

  jwtool.verify(secretJWK.signSync(msg)).then(
    function (payload) {
      assert.equal(payload.bar, 'baz')
      server.close()
    }
  ).catch(
    function (err) {
      console.error(err)
      process.exit(1)
    }
  )
}
