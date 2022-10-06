const mongoose = require("mongoose");

const cardSchema = new mongoose.Schema({
    cardNum: {
        type: Number,
    },
    name: {
        type: String,
        required: true,
        maxlength: 150,
        minlenght: 2

    },
    description: {
        type: String,
        maxlength: 255
    },
    address: {
        type: String,
        required: true,
        maxlength: 150,
        minlenght: 5
    },
    phone: {
        type: String,
        minlenght: 9,
        maxlength: 15
    },
    image: {
        type: String,
        minlenght: 2,
        maxlength: 150
    },
    userId: {
        type: String,
        required: true
    }



});

const Card = mongoose.model("card", cardSchema);
module.exports = Card;