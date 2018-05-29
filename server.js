//WARNING: This is not production code, not to be used for references, best practices
// hack api to provide file upload, jwt, email featuers on top of json server
// https://github.com/typicode/json-server

// api-server.js
//RESTful API server using json-server module
//support for enable/disable cors
//support for oauth authentication
//just for angular-reactjs-workshop

const express = require("express");
const jsonServer = require('json-server')

const jwt = require('jwt-simple');
const _ = require("lodash");
const moment = require('moment');
const nodemailer = require('nodemailer');
const jsonfile = require("jsonfile");
const multer = require('multer');

const ejs = require("ejs");
const path = require("path");
var mkdirp = require('mkdirp');

mkdirp.sync("uploads")

const app = jsonServer.create()



var storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, 'uploads')
    },
    filename: (req, file, cb) => {
        console.log("FIle ", file)
     cb(null,  Date.now() + "-" + file.originalname)
     //cb(null, file.fieldname)
    }
});

var upload = multer({storage: storage});
var serveIndex = require('serve-index')

const config = jsonfile.readFileSync("settings.json");
//console.log("Config ", config)

app.set('view engine', 'html');
app.engine('html', ejs.renderFile);
//set views directory
app.set('views', path.join(__dirname, './views'));

app.use('/node_modules', express.static('node_modules'));
    
app.use('/uploads', express.static('uploads'));
app.use('/uploads', serveIndex(__dirname + '/uploads'));


app.set('jwtTokenSecret', 'yX!fglBbZr');

app.disable("etag");

const bodyParser = require('body-parser')
app.use(bodyParser.json());


const parseArgs = require('minimist') (process.argv.slice(2))


console.log("options ", parseArgs);

var port = parseInt(parseArgs.port) || 7070;
console.log("port ", port);
var hostname = parseInt(parseArgs.host) || 'localhost';
console.log("hostname ", hostname);

//http/https
var scheme = parseInt(parseArgs.scheme) || 'http';
console.log("scheme ", scheme);


//default 24 hrs
var expiryInMinutes = parseInt(parseArgs.expiry) || 24 * 60;

console.log("expiry in minutes ", expiryInMinutes);

var offerTime = parseInt(parseArgs.offer) || 1000;

var router = jsonServer.router('./db.json')


var endPoints = [ 
    'products',
    'brands',
    'cities',
    'states',
    'stores',
    "orders"
]



app.get('/', function(req, res) {
    // now we pick end points from json file
    endPoints = []
    for (k in router.db.__wrapped__) {
        // console.log("K is ", k);
        endPoints.push(k)
    }

    res.render("index", {port, hostname, scheme, endPoints})
    
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
app.use(middlewares)
 

function authenticateUser(req, res) {
    console.log("auth ", req.body.username);
     
     

    // take from db
    var usersMatched = router.db.get("users")
    .filter(function(user) {
        return user.username == req.body.username && user.password == req.body.password; 
    })
    .take(1)
    .value()

    if (!usersMatched || usersMatched.length == 0) {
        res.sendStatus(403);
             return;
    }

    var user = usersMatched[0]
    console.log("Found user ", user);
    
    var expires = moment().add('minutes', expiryInMinutes).valueOf();
    var token = jwt.encode({
    iss: user.id,
    exp: expires
    }, app.get('jwtTokenSecret'));

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
        var decoded = jwt.decode(token, app.get('jwtTokenSecret'));

        if (decoded.exp <= Date.now()) {
            console.error("expired token");
             res.status(400).json({error: 'expired token'});
            return;
        }


            // take from db
        var usersMatched = router.db.get("users")
        .filter(function(user) {
            return user.id == decoded.iss; 
        })
        .take(1)
        .value()

        if (!usersMatched || usersMatched.length == 0) {
             console.error("user not found");
             res.status(400).json({error: 'user not found'});
             return;
        }

        var user = usersMatched[0]
        console.log("Found user ", user);

    }catch(ex) {
        console.error("unexpected error")
        res.status(400).json({error: 'may be forged token'});
        return;
    }

    console.log("valid token");
    next();
}

app.post('/oauth/token', authenticateUser);

app.use("/secured", validateToken)

app.use(function(req, res, next){
    if (req.url.indexOf("/secured") > -1) {
            req.url = req.url.replace("/secured", ""); 
             
    }   
            
    next();
})


app.use(function(req, res, next){
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

// if (commandLine.indexOf("auth") >= 0) {
//      console.log("Authentication enabled");
//      server.post('/oauth/token', authenticateUser)
//      server.use(validateToken); 
// }

app.post('/upload', upload.single('document'), (req, res, next) => {
     
    console.log("** Uploaded file ", req.file.filename);
    res.json({'message': 'File uploaded successfully',
                'result': true,
                fileName: req.file.filename,
                path: '/uploads/' +  req.file.filename, 
                url: `http://${hostname}:${port}/uploads/${req.file.filename}`
            });
    
});




app.get('/api/exist/:model/:property/:value', function(req, res){
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


app.post("/api/email", function(req, res) {
    console.log("Req body ", req.body);
    const email = req.body;
   
    // create reusable transporter object using the default SMTP transport
    let transporter = nodemailer.createTransport({
        host: config.mail.host,
        port: config.mail.port,
        secure: config.mail.secure, // true for 465, false for other ports
        auth: {
            user: config.mail.username, // generated ethereal user
            pass: config.mail.password // generated ethereal password
        }
    });

    // setup email data with unicode symbols
    let mailOptions = {
        from: config.mail.from, // sender address
        to: email.to, // list of receivers
        subject: email.subject, // Subject line
        text: email.message, // plain text body
        html: '<b>' + email.message + '</b>' // html body
    };

    console.log(mailOptions)

    console.log("Sending email ");
    // send mail with defined transport object
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log("Error sending email ", error)
             
            res.status(500).json({result: false, 
                                  error: error})
            return;
        }
        console.log('Message sent: %s', info.messageId);
        // Preview only available when sending through an Ethereal account
        console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));

        // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>
        // Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...
        
        res.json({
            result: true,
            msgId: info.messageId,
            preview: nodemailer.getTestMessageUrl(info)
        })
    });
 
});

app.use('/api', router)

var errorRouter = jsonServer.router('./logs.json')

app.use('/logs', errorRouter)

var server = require('http').Server(app);

var io = require('socket.io')(server);
io.on('connection', function(socket){
  console.log('a user connected');
   
  var handle = setInterval(function() {
       var item = router.db.get("products").sample();
        // .filter(function(m) {
        //     var m = m[property].toString().toLowerCase();
        //     return m == value;
        // })
       // .take(1)
       // .value()

      var product = _.clone(item);
      product.price = product.price - Math.floor(Math.random() * product.price);
      product.stock = Math.ceil(Math.random() * 10);

    socket.emit("offer", product)
  }, offerTime);

  socket.on('disconnect', function(){
    console.log('user disconnected');
    clearInterval(handle);
    handle = null;
  });

});


server.listen(port, function (err) {
    if (!err) {
         console.log('JSON Server is running  at ', port)
    } else {
        console.log("Error in starting REST API Server ", err);
    }
})
