// api-server.js
//RESTful API server using json-server module
//support for enable/disable cors
//support for oauth authentication
//just for angular-reactjs-workshop

const jsonServer = require('json-server')

const jwt = require('jwt-simple');
const _ = require("lodash");
const moment = require('moment');

const server = jsonServer.create()

const ejs = require("ejs");
const path = require("path");

server.set('view engine', 'html');
server.engine('html', ejs.renderFile);
//set views directory
server.set('views', path.join(__dirname, './views'));

    

server.set('jwtTokenSecret', 'yX!fglBbZr');

server.disable("etag");

const bodyParser = require('body-parser')
server.use(bodyParser.json());


const parseArgs = require('minimist') (process.argv.slice(2))


console.log("options ", parseArgs);

var port = parseInt(parseArgs.port) || 7070;

console.log("port ", port);

//default 24 hrs
var expiryInMinutes = parseInt(parseArgs.expiry) || 24 * 60;

console.log("expiry in minutes ", expiryInMinutes);


var endPoints = [ 
    'products',
    'brands',
    'cities',
    'states',
    'stores',
        "orders"
]

server.get('/', function(req, res) {


    res.render("index", {port, endPoints})
    
})

var commandLine = process.argv.join(" ").toLowerCase();
console.log("Command Line ", commandLine);

console.log(process.argv);

var defaultsOpts = {
     
}
 

if (commandLine.indexOf("nocors") >= 0) {
    defaultsOpts.noCors = true;
}

var middlewares = jsonServer.defaults(defaultsOpts)
server.use(middlewares)



var users = [
    {
        id: 1,
        name: 'Administrator',
        roles: ['admin', 'staff', 'user'],
        username: 'admin',
        password: 'admin'
    },

    {
        id:2,
        name: 'Staff',
        roles: ['staff', 'user'],
        username: 'staff',
        password: 'staff'
    },

    {
        id: 3,
        name: 'User',
        roles: ['user'],
        username: 'user',
        password: 'user'
    }
]


function authenticateUser(req, res) {
    console.log("auth ", req.body.username);
     
    var user = _.find(users, function(user) { return user.username == req.body.username && user.password == req.body.password; });

    if (!user) {
             res.sendStatus(403);
             return;
    }


    var expires = moment().add('minutes', expiryInMinutes).valueOf();
    var token = jwt.encode({
    iss: user.id,
    exp: expires
    }, server.get('jwtTokenSecret'));

    //remove password before sending to client
    var safeUser = _.clone(user);
    delete safeUser.password;

    res.json({
        token : token,
        expires: expires,
        identity: safeUser,
        token_type: 'jwt'
    }); 
}

function validateToken(req, res, next) {
    console.log("validate token");

    var bearerToken;
    
    var token = req.headers["x-auth-token"];

    if (!token) {
        if (req.headers["authorization"]) {
            token = req.headers["authorization"].split(" ")[1];
        }
    }

    if(!token) {
        console.error("token not present");
        res.status(403).json({error: 'token not present'})
        return;
    }

    try {
        var decoded = jwt.decode(token, server.get('jwtTokenSecret'));

        if (decoded.exp <= Date.now()) {
            console.error("expired token");
             res.status(400).json({error: 'expired token'});
            return;
        }

        var user = _.find(users, function(user) { return user.id == decoded.iss});

        if (!user) {
            console.error("user not found");
            res.status(400).json({error: 'user not found'});
            return;
        }
    }catch(ex) {
        console.error("unexpected error")
        res.status(400).json({error: 'may be forged token'});
        return;
    }

    console.log("valid token");
    next();
}

server.post('/oauth/token', authenticateUser);

server.use("/secured", validateToken)

server.use(function(req, res, next){
    if (req.url.indexOf("/secured") > -1) {
            req.url = req.url.replace("/secured", ""); 
             
    }   
            
    next();
})


server.use(function(req, res, next){
       if (req.url.indexOf("/delayed") > -1) {
            //delay minimum 2 - 7 seconds
            req.url = req.url.replace("/delayed", ""); 

            setTimeout(function(){
                next();      
            }, Math.floor(2 + Math.random() * 7) * 1000);
        } else {
            next();
        }
})

if (commandLine.indexOf("auth") >= 0) {
     console.log("Authentication enabled");
     server.post('/oauth/token', authenticateUser)
     server.use(validateToken); 
}

var router = jsonServer.router('./db.json')

server.get('/api/exist/:model/:property/:value', function(req, res){
    var model = req.params['model'];
    var property = req.params['property']
    var value = req.params['value'];
    
    if (!model || !value || !property || !router.db.has(model).value()) {
        res.status(422);
        res.end();
        return;
    }

    value = value.toLowerCase();

    var results = router.db.get(model)
    .filter(function(m) {
        var m = m[property].toString().toLowerCase();
        return m == value;
    })
    .take(1)
    .value()
 
    if (results.length > 0) {
        res.json({result: true})
        res.end();
        return;
    }

    return res.json({result: false})
})


server.use('/api', router)

var errorRouter = jsonServer.router('./logs.json')

server.use('/log', errorRouter)

server.listen(port, function (err) {
    if (!err) {
         console.log('JSON Server is running  at ', port)
    } else {
        console.log("Error in starting REST API Server ", err);
    }
})