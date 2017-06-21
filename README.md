# restful-server
Node.js based restful api server for Angular, React workshops

# install

  > git clone https://github.com/nodesense/restful-server


  > cd restful-server
  
  
  > npm install

To start server in port 7070, 24 hours expiry for token

  > npm start


To start server in specific port, specific  expiry minutes for token

Below start server with port number is 9090, expiry in 10 minutes

> npm start -- --port 9090  --expiry 10



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