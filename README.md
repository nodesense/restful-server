# restful-server
Node.js based restful api server for Angular, React workshops


Using json-server[https://github.com/typicode/json-server],  added JWT and Delayed end points for workshops. Please refer the json-server for detailed documentation for filter, sort, query, pagination
    

Note: Username and passwords kept transparent, servered from json file as raw data. 
In real scenarios, password and other sensitive data are not transmitted.

Note: Server doesn't do any data validation.
        Do you want to add more data, open db.json, add entries, restart the server?
        Supported methods

         
    to get all resources
    GET /api/products
    
    to get a specific resource object by id
    GET /api/products/1
    
    to create new resource, server would generate unique id
    POST /api/products 
        {followed by json data}

    to update existing resource
    PUT  /api/products/1 
        {followed by json data}

    to delete existing resource
    DELETE /api/products/1 

    to update (patch) existing resource with specific field name
    PATCH /api/products/1
            {followed by json data with specific field to update}

    

# install

  > git clone https://github.com/nodesense/restful-server


  > cd restful-server
  
  
  > npm install

  > npm start

## Start the server with different port and expiry time

To start server in localhost, port 7070 with 24 hours expiry for token

  > npm start

To start server in specific port, specific  expiry minutes for token

Below start server with port number is 9090, expiry in 10 minutes

> npm start -- --port 9090  --expiry 10



## email configuration

Update settings.json file for email server configuration. Please do not leak your personal email 
addresses

You can use below services for email.

- https://ethereal.email/  Your emails are never delivered, good for testing, development
- https://mail.yandex.com don't spam

 Non-secure configuration

```json
{
    "host": "smtp.ethereal.email",
    "port": 587,
    "secure": false,  
    "auth": {
        "user": "test",  
        "pass": "pass"  
    }
}
```


 secure configuration
 
```json
{
    "host": "smtp.ethereal.email",
    "port": 465,
    "secure": true,
    "auth": {
        "user": "test",  
        "pass": "pass"  
    }
}
```

# Email example

Caution: Please create email id free for this purpose, do not leak password in the configuration file. For testing purpose, use https://ethernal.email, your email shall not be delivered, but you have have overview of it.

If you really want to send email, I would recommend to use simple services likes Yandex email services or other similar services which provides you smtp to send email, easy and quick to create, doesn’t require phone number or complex process to create email.

### Don't leak your password, you are responsible if you are victim of fraud

To send email,

    POST /api/email    
    {
    “to”: “someone@example.com”,
    “subject”: “Welcome Email”,
    “message”: “Here your messages goes”
    }

    the server respond with id of the message, and preview url if ethernal.email used.
    

# API End Points

    http://localhost:7070/api/products
    http://localhost:7070/api/brands
    http://localhost:7070/api/cities
    http://localhost:7070/api/states
    http://localhost:7070/api/stores

# Delayed End Points (2 to 8 seconds delay)

    http://localhost:7070/delayed/api/products
    http://localhost:7070/delayed/api/brands
    http://localhost:7070/delayed/api/cities
    http://localhost:7070/delayed/api/states
    http://localhost:7070/delayed/api/stores

# Secured End Points

to login, send

            POST /oauth/token
            ..
            Content-Type: application/json

            {
                "username": "admin",
                "password": "admin"
            }
        
Server sends back token, expires and identity information

We have below user names and password.
  1. username: admin, password: admin
  2. username: staff, password: staff
  3. username: user, password: user

The below APIs must be having Authorization header with "JWT \" for all GET, POST, PUT, DELETE requests

            Authorization: JWT eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOjEsImV4cCI6MTQ5ODY1ODY4NTc4Nn0.2IuvLDf_-ipiRwQFGGX4nPNAcE1VwlX0bcLThvlUP88-p":
            
    http://localhost:7070/secured/api/products
    http://localhost:7070/secured/api/brands
    http://localhost:7070/secured/api/cities
    http://localhost:7070/secured/api/states
    http://localhost:7070/secured/api/stores


## Check if field with value exist, unique username, product etc


To Check if exists propertiess, sometimes you may want to check if a field value exist or not

Use below API for same 

    http://localhost:7070/api/exist/users/username/admin10
        

    http://localhost:7070/api/exist/products/id/1000

    
    The syntax is 
    
    http://localhost:7070/api/exist/collection-name/fieldname/expected-value

    returns json result with true or false value

    {
        "result": true
    }



## Errors and Activities

Errors and activities are kept in logs.json file, we have below end points

For Errors

    http://localhost:7070/logs/errors

For activities log,

    http://localhost:7070/logs/activities




## Upload a file

    Access All files in /uploads directory
    http://localhost:7070/uploads 

    Example, NOTE: the filename should be name="document"
  
 

    <h4>Example upload</h4>

    <form action="/upload" method="post" enctype="multipart/form-data">
        Select image to upload:
        <input type="file" name="document" id="imageToUpload">
        <input type="submit" value="Upload Image" name="submit">
    </form>
        
    
 
        Returns json response 

        {
            "message": "File uploaded successfully",
            "result": true,
            "filePath": "/uploads/1527584529745-TODO.txt"
          }

     

