const { workerData, parentPort } = require('worker_threads')
const {renderFile} = require("ejs")
const { createTransport } = require('nodemailer');
const { getNewSaltedPassword } = require('../db');
const { sign } = require('jsonwebtoken');

const transport = createTransport({
    host: process.env.MAIL_HOST,
    port: process.env.MAIL_PORT,
    auth: {
        user: process.env.MAIL_USERNAME,
        pass: process.env.MAIL_PASSWORD,
    }
});

workerData.from = `${workerData.app_name} Team <accounts@sso.tryjhumki.com>`,
workerData.subject = `${workerData.app_name}: Password reset request`

getNewSaltedPassword({email: workerData.to, password: workerData.password}, response => {
    if (!response.success) {
        req.err.push(response.message);
        return res.render("index", getViewObject(req.app_detail, req.err));
    }
    let payload = {
        id: response.user.id,
        password: response.user.salted_password,
        iat: Math.floor(Date.now() / 1000),
        nbf: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + (15 * 60)
    }
    workerData.url = `${workerData.password_reset_url}?payload=${sign(payload, response.user.password)}`;
    renderFile( './workers/template/reset-password.ejs', workerData, null, (err, string) => {
        console.log( "Error while rendering password reset email template", err );
        workerData.html = string;
        transport.sendMail(workerData, ( err, info ) => {
            console.error( err );
            console.log( info );
            transport.close();
        });
    });
});

// parentPort.postMessage( { fileName: workerData, status: 'Done' } ); 
