var connect = require('connect');
var crypto = require('crypto');
var ed25519 = require('ed25519');

var port = process.env.PORT || 3000;

var errorMessage = function (res, errMsg) {
	console.log(errMsg);
	res.end(JSON.stringify({error:errMsg}));
}

var app = connect();
app.use(connect.logger());
app.use(connect.static('static'));
app.use(connect.bodyParser());
app.use('/api/GenKey', function(req, res, next) {
	var resp = {};
	if (req.method == 'POST') {
		if (!req.body.seed) return errorMessage(res, 'seed required for POST /api/GenKey');
		try {
			var seed = crypto.createHash('sha256').update(req.body.seed).digest();
			var keyPair = ed25519.MakeKeypair(seed);
			resp.publicKey = keyPair.publicKey.toString('base64');
			resp.privateKey = keyPair.privateKey.toString('base64');
		} catch (err) {
			resp.errorMessage = err.message;
		}
	} else {
		try {
			var seed = crypto.randomBytes(32);
			var keyPair = ed25519.MakeKeypair(seed);
			resp.publicKey = keyPair.publicKey.toString('base64');
			resp.privateKey = keyPair.privateKey.toString('base64');
		} catch (err) {
			resp.errorMessage = err.message;
		}
	}
	return res.end(JSON.stringify(resp));
});
app.use('/api/Sign', function (req, res, next) {
	var err = function (msg) {errorMessage(res, msg);}
	if (req.method != 'POST') return err('Must be a post');
	if (!req.body.privateKey) return err('Missing privateKey');
	if (!req.body.message) return err('Missing message');
	var resp = {};
	try {
		var privateKey = new Buffer(req.body.privateKey, 'base64');
		var message = new Buffer(req.body.message, 'utf8');
		resp.signature = ed25519.Sign(message, {privateKey: privateKey}).toString('base64');
	} catch (e) {
		return err(e.message);
	}
	return res.end(JSON.stringify(resp));
});
app.use('/api/Verify', function (req, res, next) {
	var err = function (msg) {errorMessage(res, msg);}
	if (req.method != 'POST') return err('Must be a post');
	if (!req.body.message) return err('Missing message');
	if (!req.body.signature) return err('Missing signature');
	if (!req.body.publicKey) return err('Missing publicKey');
	var resp = {};
	try {
		var message = new Buffer(req.body.message, 'utf8');
		var signature = new Buffer(req.body.signature, 'base64');
		var publicKey = new Buffer(req.body.publicKey, 'base64');
		resp.result = ed25519.Verify(message, signature, publicKey);
	} catch (e) {
		return err(e.message);
	}
	return res.end(JSON.stringify(resp));
});


app.listen(port, function () {
	var addy = this.address();
	console.log("App listening on", addy.address+":"+addy.port);
});
