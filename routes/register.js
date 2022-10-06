const express = require("express");
const router = express.Router();
const joi = require("joi");
const bcrypt = require("bcrypt");
const User = require("../models/User");
const jwt = require("jsonwebtoken");

let strongPassword = new RegExp('(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])')
const registerSchema = joi.object({
    name: joi.string().required().min(2),
    email: joi.string().required().email().max(50),
    password: joi.string().required().min(8),
    biz: joi.boolean().required(),
});

function isStrongPassword(password) {
    return strongPassword.test(password)
}


// 1 - sign up 
router.post("/", async (req, res) => {
    try {
        // joi validation
        const {
            error
        } = registerSchema.validate(req.body);
        if (error) return res.status(400).send(error.message);
        // check password strength
        if (!isStrongPassword(req.body.password))
            return res.status(400).send("password must contain: one lowercase letter , one uppercase letter , one digit and one special character ")

        // user exists
        let user = await User.findOne({
            email: req.body.email
        });
        if (user) return res.status(400).send("user already exists");

        // add new user
        user = new User(req.body);

        // encrypt password
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(user.password, salt);



        // create token that contain id and biz 
        const genToken = jwt.sign({
                _id: user._id,
                biz: user.biz
            },
            process.env.jwtKey
        );


        await user.save();
        return res.status(201).send({
            token: genToken
        });
    } catch (error) {
        return res.status(400).send("error in register: " + error.message);
    }
});

module.exports = router;