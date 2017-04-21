var settings = require('./config/config.json');

var bodyParser = require('body-parser');
var jwt = require('jwt-simple');
var moment = require('moment');
var LdapAuth = require('ldapauth-fork');
var Promise  = require('promise');
var express = require('express');
var path = require('path');

app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(require('cors')());

app.use('/', express.static(path.join(__dirname, '/swagger')))

if (settings.hasOwnProperty('jwt') && settings.jwt.hasOwnProperty('secret')) {
    console.log("Loaded JWT secret from config");
    app.set('jwtTokenSecret', settings.jwt.secret);
}
else if (process.env.hasOwnProperty('JWT_SECRET')) {
    console.log("Loaded JWT secret from environment");
    app.set('jwtTokenSecret',process.env.JWT_SECRET);
}
else {
    console.error("JWT secret not specified in config or environment. Set JWT_SECRET to your secret before starting this service.");
    process.exit(1);
}

var authenticate = function (username, password) {
    return new Promise(function (resolve, reject) {
        var auth = new LdapAuth(settings.ldap);
        auth.on('error', function (err) {
            console.error('LdapError: '+ err.code);
        });
        // hacked this to skip the auth and just fetch the user data.
        auth._findUser(username, function(err, user) {
            if(err)
                reject(err);
            else if (!user)
                reject();
            else
                resolve(user);
        });
    });
};

app.post('/authenticate', function (req, res) {
    if(req.body.username && req.body.password) {
        authenticate(req.body.username, req.body.password)
            .then(function(user) {
                var expires = parseInt(moment().add(1, 'days').format("X"));
                var token = jwt.encode({
                    exp: expires,
                    user_name: user.uid,
                    full_name: user.displayName,
                    mail: user.mail
                }, app.get('jwtTokenSecret'));

                console.log("Generated JWT for "+user.uid+" expiring "+expires)
                res.json({token: token, user_name: user.uid});
            })
            .catch(function (err) {
                if (err.name === 'InvalidCredentialsError') {
                    console.log("Invalid password for: "+req.body.username);
                    res.status(401).send({ error: 'Wrong user or password'});
                }
                else if (typeof err === 'string' && err.match(/no such user/i)) {
                    console.log("No such user: "+req.body.username);
                    res.status(401).send({ error: 'Wrong user or password'});
                }
                else {
                    console.log("Unexpected error: ", err);
                    res.status(500).send({ error: 'Unexpected Error'});
                    auth = new LdapAuth(settings.ldap);
                }
            });
        } else {
            console.log("No username or password supplied to authenticate")
            res.status(400).send({error: 'No username or password supplied'});
        }
});

app.post('/verify', function (req, res) {
    var token = req.body.token;
    if (token) {
        try {
            var decoded = jwt.decode(token, app.get('jwtTokenSecret'));
            if (decoded.exp <= parseInt(moment().format("X"))) {
                console.log("JWT has expired for "+decoded.user_name)
                res.status(400).send({ error: 'Access token has expired'});
            } else {
                console.log("Verified JWT for "+decoded.user_name+" expiring "+decoded.exp)
                res.json(decoded)
            }
        } catch (err) {
            console.log("JWT "+token+" cannot be decoded")
            res.status(500).send({ error: 'Access token could not be decoded'});
        }
    } else {
        res.status(400).send({ error: 'Access token is missing'});
    }
});


var port = (process.env.PORT || 3000);
app.listen(port, function() {
    console.log('Listening on port: ' + port);

    if (typeof settings.ldap.reconnect === 'undefined' || settings.ldap.reconnect === null || settings.ldap.reconnect === false) {
        console.warn('WARN: This service may become unresponsive when ldap reconnect is not configured.')
    }
});
