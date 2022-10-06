const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    userId: {
        type: String,
        require: true,
    },
    name: {
        type: String,
        required: true,
        minlength: 2,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        maxlength: 50
    },
    password: {
        type: String,
        required: true,
        minlength: 8,
    },
    biz: {
        type: Boolean
    },
});

const User = mongoose.model("user", userSchema);
module.exports = User;