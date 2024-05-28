const { workerData, parentPort } = require('worker_threads')
const {renderFile} = require("ejs")
const { createTransport } = require('nodemailer');

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

renderFile( './workers/template/password-updated.ejs', workerData, null, (err, string) => {
    console.log( "Error while rendering password updated email template", err );
    workerData.html = string;
    transport.sendMail(workerData, console.log);
});

parentPort.postMessage( { fileName: workerData, status: 'Done' } ); 
