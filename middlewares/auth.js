const jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
    try {
        // get the token
        let token = req.header("Authorization");
        if (!token) return res.status(401).send("Access denied. no token provided");

        // check the token
        let payload = jwt.verify(token, process.env.jwtKey);
        // save the payload
        req.payload = payload;
        next();
    } catch (error) {
        res.status(401).send(error.message + "");
    }
};