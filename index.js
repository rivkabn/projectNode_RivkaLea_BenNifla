const express = require("express");
require("dotenv").config();
const mongoose = require("mongoose");
const register = require("./routes/register");
const login = require("./routes/login");
const profile = require("./routes/profile");
const cards = require("./routes/cards");
const cors = require("cors");

const PORT = process.env.PORT || 8000;
const app = express();

app.use(express.json());

mongoose
    .connect(process.env.db, {
        useNewUrlParser: true
    })
    .then(() => console.log("MongoDB connected"))
    .catch((err) => console.log(err));

app.use("/api/register", register);
app.use("/api/login", login);
app.use("/api/profile", profile);
// app.use("/api/products", products);
app.use("/api/cards", cards);
app.use(cors());

app.listen(PORT, () => console.log("Server started on port", PORT));