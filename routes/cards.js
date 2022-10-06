const express = require("express");
const auth = require("../middlewares/auth");
const _ = require("lodash");
const joi = require("joi")
const Card = require("../models/Card");
const {
    default: mongoose
} = require("mongoose");
const router = express.Router();

const cardSchema = joi.object({
    name: joi.string().required().min(2).max(150),
    description: joi.string().max(255).max(255),
    address: joi.string().required().min(5).max(150),
    phone: joi.string().min(9).max(15),
    image: joi.string().min(2).max(150),

});

const cardSchemaForUpdate = joi.object({
    name: joi.string().min(2).max(150),
    description: joi.string().max(255).max(255),
    address: joi.string().min(5).max(150),
    phone: joi.string().min(9).max(15),
    image: joi.string().min(2).max(150),
});

// 4 - create  new card
router.post("/", auth, async (req, res) => {
    try {
        // joi validation
        const {
            error
        } = cardSchema.validate(req.body);
        if (error) return res.status(400).send(error.message);
        // if card not exists for this user: unique  ( name, address, userId )
        let card = await Card.findOne({
            name: req.body.name,
            address: req.body.address,
            userId: req.payload._id
        });
        if (card) return res.status(400).send("card already exists for this user");
        // add new card
        card = new Card(req.body)
        // create random id for card
        let ranNum;
        do {
            ranNum = _.random(1, 1000000)
            let card2 = await Card.find({
                cardNum: ranNum
            })

        } while (await Card.findOne({
                cardNum: ranNum
            }))
        // save card
        card.cardNum = ranNum
        card.userId = req.payload._id;
        await card.save();
        res.status(201).send(_.pick(card, ["cardNum", "userId", "name", "phone", "description", "address ", "img"]))
    } catch (error) {
        res.status(400).send(error);
    }
});

// 8 - get array of all the cards for a given user 
router.get("/myCards", auth, async (req, res) => {
    try {
        let cards = await Card.find({
            userId: req.payload._id
        })
        res.status(200).send(cards)
    } catch (error) {
        res.status(400).send(error.message + "in cards")
    }
})

// 5 -  print card details for a given card Id 
router.get("/:id", auth, async (req, res) => {
    try {
        // the following "if" is required to avoid the cast error with not existing id
        if (req.params.id.match(/^[0-9a-fA-F]{24}$/)) { //checks if 24 hexadecimals  numbers
            let card = await Card.findById(
                req.params.id
            );
            if (!card) return res.status(404).send("Wrong details");
            res.status(200).send(_.pick(card, ["name", "address", "img", "cardNum", "userId", "description"]));
        } else {
            res.status(404).send("card id does not exist")
        }
    } catch (error) {
        res.status(400).send(error + " in cards");
    }
});

// 6 - get id and change details
// allowed  only for the owner of the card
router.put("/:id", auth, async (req, res) => {
    try {
        // joi validation:
        const {
            error
        } = cardSchemaForUpdate.validate(req.body)
        if (error) return res.status(400).send(error.message);

        // update card:
        // the following "if" is required to avoid the cast error with not existing id
        if (req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
            x = req.payload._id
            let card = await Card.findOneAndUpdate({
                _id: req.params.id,
                userId: req.payload._id
            }, req.body, {
                new: true
            });
            if (!card) return res.status(404).send("Cannot update, card not found for this user");
            res.status(200).send(card);
        } else {
            res.status(404).send("card id must have 24 caracteres")
        }
    } catch (error) {
        res.status(400).send(error + ", cannot update card");
    }
});

// 7 - delete card with the id
// allowed only for the owner of the card
router.delete("/:id", auth, async (req, res) => {
    try {
        // the follow "if" is needed to avoid cast error if the id doesn't exist
        if (req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
            // it is allowed to delete only if the card belongs to the user
            let card = await Card.findOneAndDelete({
                _id: req.params.id,
                userId: req.payload._id
            }, req.body);
            if (!card) return res.status(404).send("Cannot delete, card not found for this user");
            res.status(200).send("card deleted successfully");
        } else {
            res.status(404).send("cannot delete because card not found")
        }
    } catch (error) {
        res.status(400).send(error + ", cannot deleted card");
    }
});




// 9 -  print all cards
router.get("/", auth, async (req, res) => {
    try {
        let cards = await Card.find();
        res.status(200).send(cards);

    } catch (error) {
        res.status(400).send(error.message + " in print cards")
    }
})

module.exports = router;