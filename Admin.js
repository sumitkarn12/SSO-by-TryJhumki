const express = require("express");
const auth_app = express.Router()
const {verify} = require("jsonwebtoken")
require('dotenv').config();
const db = require("./db")

auth_app.use((req, res, next) => {
    const token = req.cookies.access_token;
    if (!token) return res.redirect("/");
    try {
        req.logged_user = verify(token, process.env.JWT_SECURITY_KEY);
        return next();
    } catch (e) {
        res.redirect("/");
    }
});
auth_app.get("/", function (req, res) {
    db.getApps(req.logged_user.id,apps =>  res.render("app", { 'apps': apps }) );
});

auth_app.post("/", function (req, res) {
    let app_details = req.body;
    app_details.owner = req.logged_user.id;
    if (!app_details.id)
        db.createApp(app_details, response =>  res.redirect("/app") );
    else
        db.updateApp(app_details, response =>  res.redirect("/app") );
});
auth_app.post("/delete", function (req, res) {
    let app_details = req.body;
    app_details.owner = req.logged_user.id;
    if (app_details.id)
        db.deleteApp(app_details, response =>  res.redirect("/app") );
    else
        res.redirect("/app");
});

module.exports = auth_app;