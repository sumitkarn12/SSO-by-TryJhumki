const express = require("express");
const app = express();
const auth_app = require("./AuthApp")
const auth = require("./Auth")
const cors = require("cors")
const jwt = require("jsonwebtoken");
const bodyParser = require('body-parser')
require('dotenv').config();
const cookieParser = require("cookie-parser");

app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())
app.use(cors())
app.use(cookieParser());
app.use(express.static('public'))
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.set("view engine", "ejs");

app.get("/", function (req, res) {
    res.redirect( `/auth/v1/${process.env.SSO_APP_ID}` );
});

app.use("/app", auth_app );
app.use("/auth/v1", auth );

app.listen( process.env.PORT || 3000, (req, res) => {
    console.log("App is running on port 3000");
});