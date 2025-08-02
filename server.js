const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');

app.use(cors());

const users = [
    {
        userId: 1,
        password: 1234
    },
    {
        userId: 2,
        password: 4567
    }
];

const secretKey = "pookie0817";

/*
    JWT : JSON Web Token is a is a standard used to securely transmit information between a client (like a frontend application) and a server (the backend). It is commonly used to verify users' identities, authenticate them, and ensure safe communication between the two. JWTs are mainly used in web apps and APIs to protect against unauthorized access.

    The data in a JWT, such as user details, is stored in a simple JSON format. To keep the data safe, the token is signed cryptographically, making sure that no one can alter it.

    How JWT Token works?
    1. Client sends a login request to the server with the user credentials.
    2. Server checks if the user is valid or not by checking in the database - if the user is present or not.
    3. If yes then server creates a JWT Token and sends it back to the client, but if not then it emits an error message.
    4. Client then stores this token either in the localDB or in cookies.
    5. Now whenever the client calls any API, it sends the token in the authorization header with "Bearer <token>".
    6. This token is fetched along with the request body but first, the JWT verification takes place.
    7. The token is checked if it verifies then request is further processed else server gives 401 status code message i.e. unauthorized.

    What is a JWT Token?
    JWT Token is an encoded 3 part string separated with period '.'
    Example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsInBhc3N3b3JkIjoxMjM0LCJpYXQiOjE3NTQxNDMxODUsImV4cCI6MTc1NDE0MzMwNX0.7Z_e5h_CrGh-PYnfS85kqC1t51NOPQ8StnslEMA3XK0

    Structure Of JWT:- 
    1. Header: The header contains metadata about the token, including the signing algorithm and token type here metadata means data about data.

    {
        "alg": "HS256",
        "typ": "JWT"
    }

    alg: Algorithm used for signing (e.g., HS256, RS256).
    typ: Token type, always "JWT".
    Base64Url Encoded Header: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9

    2. Payload(claim): The payload contains the information about the user also called as a claim and some additional information including the timestamp at which it was issued and the expiry time of the token.

    {
        "userId": 123,
        "role": "admin",
        "exp": 1672531199
    }

    Common claim types:
    iss (Issuer): Identifies who issued the token.
    sub (Subject): Represents the user or entity the token is about.
    aud (Audience): Specifies the intended recipient.
    exp (Expiration): Defines when the token expires.
    iat (Issued At): Timestamp when the token was created.
    nbf (Not Before): Specifies when the token becomes valid.

    Base64Url Encoded Payload: eyJ1c2VySWQiOjEsInBhc3N3b3JkIjoxMjM0LCJpYXQiOjE3NTQxNDMxODUsImV4cCI6MTc1NDE0MzMwNX0

    3. Signature: The signature ensures token integrity and is generated using the header, payload, and a secret key. A signature is created by encoding header, payload and the secret_key.

    A secret_key can be anything like car123, thriller, ferrari66. This secret_key is stored at the server.

    HMACSHA256(
        base64UrlEncode(header) + "." + base64UrlEncode(payload),
        secret
    )

    What Happens under the hood?
    1. When the client sends the user credentials, it is validated then a JWT Token is created.
    2. When verifying the token sent by the client on another API call, the header and payload is decoded and again encoded by server with its secret_key.
    3. If the encoded string matches the signature then we can say the JWT Token is valid else it is tampered.
    4. Also the validity of the token is checked means is the token expired or not?

    Due to JWT the authentication process gets fast and also very lightweighted as there is no read/write DB task. Means because of JWT, the server doesn't have to go to the DB and check for user at every API call, the server did this work at the login time and generated a token. Now, if the token is valid then we can say that the user is valid and due to the token we can get the user's credentials anytime for a DB search or other operations.

    Good Practices:-
    Always give a small time expiry time for JWT Tokens.
    Use small crendials in claim for fast and lightweight request.

    There is a concept called refresh tokens. Which is very secure.
    Refresh token means setting the expiry time of the token to a very short period and if the user is using the app for a long time then renewing and storing the access token continuously by using a long time token. 
*/

// This method takes user credentials and validates the user, then returns a JWT token if valid user.
app.post('/auth/login', (req, res) => {

    // Storing the user credentials in claim because we are going to use this as claimp(payload) of our JWT token. This request body contains { userId, password }
    const claim = req.body;

    // Checking for a user matching the userId and password from request.
    for (let index = 0; index < users.length; index++) {
        const user = users[index];

        // If the user exists then create a token and send it as a response with a confirmation message
        if (user.userId === claim.userId && user.password === claim.password) {

            // jwt.sign() method takes claim(payload), secret_key and some jwt signOptions like iat, exp, issuer,etc and creates a JWT token. 
            const token = jwt.sign(claim, secretKey, { expiresIn: "2 mins" });

            // The JWT Token is then sent as a response with a message to the client.
            res.status(200).json({
                token: token,
                msg: "User loggedin successfully"
            });
            return;
        }
    }
    res.status(401).json({ msg: "User Not found" });
});

// This API returns a list of all users
app.get('/users', (req, res) => {

    // Client sends an authorization header like this in string: 'Bearer <token>' for every API call.
    // This authorization header contains the JWT Token which is then retrieved.
    console.log("Authorization Header : ", req.headers.authorization);

    // The token is reteieved here
    const token = req.headers.authorization.split(" ")[1];
    console.log(token);

    // This method authorizes the user by verifying the JWT Token
    authorizeRequest(token, res);
});

function authorizeRequest(token, res) {
    try {

        // jwt.verify() method takes token and secret_key. 
        // It then checks if the Token is valid or not
        // If it is valid then it returns the decoded claim else it returns an error stating the cause, it may be JWT expriry or some tampering.
        const result = jwt.verify(token, secretKey);
        console.log("result : ", result);
        res.status(200).json({
            users: users
        });
    } catch (error) {
        console.log(error);
        res.status(404).json({
            msg: "No data"
        });
    }
}

app.listen(5000, () => console.log("Server started"));