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

app.set('jwtTokenSecret', settings.jwt.secret);

var authenticate = function (username, password) {
    return new Promise(function (resolve, reject) {
        var auth = new LdapAuth(settings.ldap);
        auth.authenticate(username, password, function (err, user) {
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
                var expires = moment().add(2, 'days').valueOf();
                var token = jwt.encode({
                    exp: expires,
                    user_name: user.uid,
                    full_name: user.displayName,
                    mail: user.mail
                }, app.get('jwtTokenSecret'));

                res.json({token: token, user_name: user.uid});
            })
            .catch(function (err) {
                console.log(err);
                if (err.name === 'InvalidCredentialsError' || (typeof err === 'string' && err.match(/no such user/i)) ) {
                    res.status(401).send({ error: 'Wrong user or password'});
                }
                else {
                    res.status(500).send({ error: 'Unexpected Error'});
                    auth = new LdapAuth(settings.ldap);
                }

            });
        } else {
            res.status(400).send({error: 'No username or password supplied'});
        }
});

app.post('/verify', function (req, res) {
    var token = req.body.token;
    if (token) {
        try {
            var decoded = jwt.decode(token, app.get('jwtTokenSecret'));
            if (decoded.exp <= Date.now()) {
                res.status(400).send({ error: 'Access token has expired'});
            } else {
                res.json(decoded)
            }
        } catch (err) {
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
