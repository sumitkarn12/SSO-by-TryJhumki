const express = require("express");
const auth = express.Router();
const jwt = require("jsonwebtoken");
require('dotenv').config();
const db = require("./db")
const { Worker } = require('worker_threads');

auth.use(["/:app_id", "/:app_id/*"], (req, res, next) => {
    req.params.app_id = +req.params.app_id;
    req.body.app_id = +req.body?.app_id;
    db.getApp(req.params.app_id, response => {
        console.log( response )
        req.err = [];
        req.app_detail = null;
        if (response.success) {
            req.app_detail = response.app_detail;
        } else {
            req.err.push(response.message);
        }
        next();
    });
});

function getViewObject(app_detail, message_array = []) {
    return Object.assign({
        id: null,
        app_name: "SSO by tryJhumki",
        app_logo: "https://i.ibb.co/nRFq70R/Logo-of-Try-Jhumki.png",
        redirect_uri: "http://localhost:3000/app"
    }, app_detail, {
        err: message_array.filter( a => a != null )
    });
}

auth.get("/logout", (req, res) => {
    return res.clearCookie("access_token").status(200).redirect("/");
})

auth.get("/callback", (req, res) => {
    let token = req.query.token;
    let validatedPayload = null;
    try {
        validatedPayload = jwt.verify(token, process.env.JWT_SECURITY_KEY);
        if (validatedPayload.app_id != req.params.app_id)
            res.status(401).send(`Invalid payload.`);
    } catch (error) {
        return res.status(401).send(error.message);
    }

    if (validatedPayload) {
        return db.getUser(validatedPayload.id, response => {
            if (!response.success) {
                return res.status(403).send( response.message );
            }
            response.iat = Math.floor( Date.now()/1000 )
            response.nbf = Math.floor( Date.now()/1000 )
            response.exp = Math.floor( Date.now()/1000 ) + ( 60*1 )
            const signedToken = jwt.sign(response.user, process.env.JWT_SECURITY_KEY);
            return res.cookie("access_token", signedToken, { httpOnly: true, secure: true })
              .status(200)
              .redirect("/app");
        });
    }
    res.status(403).json({ success: false, message: req.err });
});

auth.get("/:app_id", function (req, res) {
    let obj = getViewObject(req.app_detail, req.err);
    console.log( obj );
    res.render( "index", obj );
});
auth.post("/:app_id/login", function (req, res) {
    db.validateUser(req.body, response => {
        req.err.push(response.message);
        if (response.success) {
            let payload = {
                iat: Math.floor(Date.now() / 1000),
                nbf: Math.floor(Date.now() / 1000),
                exp: Math.floor(Date.now() / 1000) + (15 * 60)
            }
            payload.id = response.user.id,
            payload.app_id = response.user.app_id
            let uri = req.app_detail.redirect_uri+"?token="+jwt.sign(payload, process.env.JWT_SECURITY_KEY); 
        
            return res.redirect( uri );
        }
        res.render("index", getViewObject(req.app_detail, req.err));
    });
});
auth.post("/:app_id/register", function (req, res) {
    db.createUser(req.body, response => {
        req.err.push(response.message)
        res.render("index", getViewObject(req.app_detail, req.err));
    });
});
auth.get("/:app_id/user", function (req, res) {
    let token = req.query.token;
    let validatedPayload = null;
    res.type('json')
    try {
        validatedPayload = jwt.verify(token, process.env.JWT_SECURITY_KEY);
        if (validatedPayload.app_id != req.params.app_id)
            req.err.push(`Invalid payload.`);
    } catch (error) { req.err.push(error.message); }

    if (validatedPayload) {
        return db.getUser(validatedPayload.id, response => {
            if (!response.success) {
                res.status(403);
            }
            res.json(response);
        });
    }
    res.status(403).json({ success: false, message: req.err });
});
auth.post("/:app_id/password/forgot", function (req, res) {
    let password_reset_url = `${req.protocol}://sso.tryjhumki.com/auth/v1/${req.params.app_id}/password/forgot`;
    if (req.hostname == 'localhost')
        password_reset_url = password_reset_url.replace('sso.tryjhumki.com', `localhost:${3000}`);

    if (req.body.password1 !== req.body.password2) {
        req.err.push(`New Password and Confirm Password does not match.`);
        return res.render("index", getViewObject(req.app_detail, req.err));
    }
    const worker = new Worker( './workers/send_password_reset_info.js', {
        workerData: {
            app_logo: req.app_detail.app_logo,
            app_name: req.app_detail.app_name,
            url: password_reset_url,
            to: req.body.email,
            password: req.body.password1,
            password_reset_url: password_reset_url
        }
    });
    req.err.push( `You should receive an email to reset password of your account.` );
    return res.render("index", getViewObject(req.app_detail, req.err));
});
auth.get("/:app_id/password/forgot", function (req, res) {
    req.app_detail.payload = req.query.payload;
    return res.render("reset_password", getViewObject(req.app_detail, req.err));
});
auth.post("/:app_id/password/reset", function (req, res) {
    req.app_detail.payload = req.body.payload;
    let decodedPayload = null;
    try { decodedPayload = jwt.decode(req.app_detail.payload); }
    catch (error) {
        req.err.push(error.message);
        return res.render("reset_password", getViewObject(req.app_detail, req.err));
    }
    db.getUser(decodedPayload.id, function (response) {
        if (response.success) {
            try {
                let verifiedToken = jwt.verify(req.app_detail.payload, response.user.password);
                return db.setNewSaltedPassword({ id: decodedPayload.id, password: verifiedToken.password }, updatedResponse => {
                    if ( updatedResponse.success ) {
                        const worker = new Worker( './workers/send_password_updated_info.js', {
                            workerData: {
                                app_logo: req.app_detail.app_logo,
                                app_name: req.app_detail.app_name,
                                to: response.user.email
                            }
                        });
                    }
                    req.err.push(updatedResponse.message);
                    return res.render("index", getViewObject(req.app_detail, req.err));
                });
            } catch (error) {
                req.err.push(error.message);
            }
        }
        return res.render("reset_password", getViewObject(req.app_detail, req.err));
    })
});

module.exports = auth;