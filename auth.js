const argon2 = require("argon2");
const jwt = require('jsonwebtoken');
require("dotenv").config();

// hashing the password
const hashingOptions = {
    type: argon2.argon2id,
    memoryCost: 2 ** 16,
    timeCost: 5,
    parallelism: 1,
}

const hashPassword = (req, res, next) => {
   argon2
   .hash(req.body.password, hashingOptions)
   .then((hashedPassword) => {
    req.body.hashedPassword = hashedPassword;
    delete req.body.password;

    next();
   })
   .catch((err) => {
    console.error(err);
    res.sendStatus(500);
   });
  };

  // verifying the password
  const verifyPassword = (req, res) => {
    argon2
    .verify(req.user.hashedPassword, req.body.password)
    .then((isVerified) => {
      if (isVerified) {
        const payload = { sub: req.user.id };

        const token = jwt.sign(payload, process.env.JWT_SECRET, {
          expiresIn: "1h",
        });

        delete req.user.hashedPassword;
        res.send({ token, user: req.user});
    } else {
      res.sendStatus(401);
    }
    })
    .catch((err) => {
      console.error(err);
      res.sendStatus(500);
    })
  }

  // verifying the token
  const verifyToken = (req, res, next) => {
    try{
      const authHeader = req.get('Authorization'); //get the "Authorization" header from the request

      if (authHeader == null) {
        throw new Error('Authorization header is missing'); //throw an error if the header is missing
      }

      const [type, token] = authHeader.split(' '); //split the header string into type and token

      if (type !== "Bearer") {
        throw new Error("Authorization header does not contain 'Bearer' type"); //throw an error if the type is not "Bearer"
      }

      req.payload = jwt.verify(token, process.env.JWT_SECRET); //verify the token synchronously: if it's valid, fill req.payload with the decoded payload

      next();
    } catch (err) {
      console.error(err);
      res.sendStatus(401);
    }
  };


  module.exports = {
    hashPassword,
    verifyPassword,
    verifyToken,
  };