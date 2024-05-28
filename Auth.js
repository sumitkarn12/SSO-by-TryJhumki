const express = require("express");
const auth = express.Router();
const jwt = require("jsonwebtoken");
require('dotenv').config();
const db = require("./db")
const {renderFile} = require("ejs")
const { createTransport } = require('nodemailer');
const { Worker } = require('worker_threads');

const transport = createTransport({
    host: process.env.MAIL_HOST,
    port: process.env.MAIL_PORT,
    auth: {
        user: process.env.MAIL_USERNAME,
        pass: process.env.MAIL_PASSWORD,
    }
});

const email_template = function (obj) {
    return `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
    <html xmlns="http://www.w3.org/1999/xhtml">
    <head>
      <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Reset account password</title>
    </head>
    <body style="font-family: Helvetica, Arial, sans-serif; margin: 0px; padding: 0px; background-color: #ffffff;">
      <table role="presentation" style="width: 100%; border-collapse: collapse; border: 0px; border-spacing: 0px; font-family: Arial, Helvetica, sans-serif; background-color: rgb(239, 239, 239);">
        <tbody>
          <tr>
            <td align="center" style="padding: 1rem 2rem; vertical-align: top; width: 100%;">
              <table role="presentation" style="max-width: 600px; border-collapse: collapse; border: 0px; border-spacing: 0px; text-align: left;">
                <tbody>
                  <tr>
                    <td style="padding: 40px 0px 0px;">
                      <div style="text-align: left;">
                        <div style="padding-bottom: 20px;">
                          <img src="${obj.app_logo}" alt="${obj.app_name} logo" style="width: 56px; border-radius: 50%; border: 1px solid gray; padding: 8px;" />
                        </div>
                      </div>
                      <div style="padding: 20px; background-color: rgb(255, 255, 255); border-radius: 16px;">
                        <div style="color: rgb(0, 0, 0); text-align: left;">
                          <p>Click the below button to reset your account password.</p>
                          <a href="${obj.url}" style="font-size: 16px; font-weight: bold; text-decoration:none; color:#000;">
                            <p style="padding: 16px; background-color: rgb(239, 239, 239); text-align:center; border-radius: 12px;">Reset password</p>
                          </a>
                          <p style="padding-bottom: 16px">If you didn’t request this, you can ignore this email.</p>
                          <p>Thanks,<br>The ${obj.app_name} Team</p>
                        </div>
                      </div>
                      <div style="padding-top: 20px; color: rgb(153, 153, 153); text-align: center;">
                        <p style="padding-bottom: 16px">Made with ♥ in India</p>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </td>
          </tr>
        </tbody>
      </table>
    </body>
    </html>`;
}

auth.use(["/:app_id", "/:app_id/*"], (req, res, next) => {
    req.params.app_id = +req.params.app_id;
    req.body.app_id = +req.body?.app_id;
    db.getApp(req.params.app_id, response => {
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
    res.render("index", getViewObject(req.app_detail, req.err));
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
                return db.setNewSaltedPassword({ id: decodedPayload.id, password: verifiedToken.password }, response => {
                    req.err.push(response.message);
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