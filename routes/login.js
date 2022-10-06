const express = require("express");
const router = express.Router();
const joi = require("joi");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

let strongPassword = new RegExp('(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])')

function isStrongPassword(password) {
    return strongPassword.test(password)
}

const loginSchema = joi.object({
    email: joi.string().required().email().max(50),
    password: joi.string().required().min(8)
});

router.post("/", async (req, res) => {
    try {
        // joi validation
        const {
            error
        } = loginSchema.validate(req.body);
        if (error) {
            return res.status(400).send(error.message);
        }
        // check password strength
        if (!isStrongPassword(req.body.password))
            return res.status(400).send("password must contain: one lowercase letter , one uppercase letter , one digit and one special character ")

        // check exist user
        let user = await User.findOne({
            email: req.body.email
        });
        if (!user) return res.status(400).send("wrong password or email");

        // check password
        const compareResult = await bcrypt.compare(
            req.body.password,
            user.password
        );
        if (!compareResult) return res.status(400).send("wrong password or email");

        // create token that contain biz and _id
        const genToken = jwt.sign({
                _id: user._id,
                biz: user.biz
            },
            process.env.jwtKey
        );


        res.status(200).send({
            token: genToken
        });
    } catch (error) {
        res.status(400).send("ERROR in login" + error);
    }
});

module.exports = router;