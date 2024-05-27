// Get the client
const mysql = require('mysql2');
require('dotenv').config();
const crypto = require( "crypto" );

// Create the connection to database
const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
});

exports.createApp = function( app_detail, callback ) {
    connection.query(
        "INSERT into apps (app_name,app_logo, redirect_uri,owner) values(?,?, ?,?)", [ app_detail.app_name, app_detail.app_logo, app_detail.redirect_uri, app_detail.owner ],
        function (err, results) {
            if ( err )
                throw err
            callback({ message: `${results.affectedRows} rows inserted` })
        }
    );
}
exports.updateApp = function( app_detail, callback ) {
    connection.query(
        "UPDATE apps set app_name = ?, app_logo = ?, redirect_uri = ? where id =? and owner = ?",
        [ app_detail.app_name, app_detail.app_logo, app_detail.redirect_uri, app_detail.id, app_detail.owner ],
        function (err, results) {
            if ( err )
                throw err
            callback({ message: `${results.affectedRows} rows inserted` })
        }
    );
}
exports.deleteApp = function( app_detail, callback ) {
    connection.query(
        "DELETE from apps where id =? and owner = ?",
        [ app_detail.id, app_detail.owner ],
        function (err, results) {
            if ( err )
                throw err
            callback({ message: `${results.affectedRows} rows inserted` })
        }
    );
}
exports.getApps = function(owner, callback ) {
    connection.query( "select * from apps where owner = ?", [owner], function (err, results) {
        if ( err ) throw err;
        callback( results );
    });
}
exports.getApp = function( id, callback ) {
    connection.query( "select * from apps where id = ?", [ id ], function (err, results) {
        if ( err ) return callback({ success: false, message: err.sqlMessage });
        if ( !results[0] ) return callback({ success: false, message: `No app found with ${id}` });
        callback({ success: true, app_detail: results[0] });
    });
}

exports.createUser = function( user, callback ) {
    user.salt = Math.floor(Math.random() * 999999999);
    user.salted_password = crypto.createHash("sha256").update(user.password + user.salt).digest("hex");
    connection.query( "INSERT into users (email,password,salt,name) values( ?, ?, ?, ? )",
    [ user.email, user.salted_password, user.salt, user.name ], function (err, results) {
        if ( err ) return callback({ success: false, message: err.sqlMessage })
        callback({ success: true, message: `User created with ${user.email}. Please sign in.` })
    });
}
exports.validateUser = function( user, callback ) {
    connection.query(`SELECT * from  users where email = ?`,[ user.email ], ( err, results ) => {
        if ( err ) return callback({ "success": false, "message": err.sqlMessage });
        if ( !results[0] ) return callback({ "success": false, "message": `No user found with email ${user.email}` })
        results = results[0];
        const salted_password = crypto.createHash("sha256").update(user.password + results.salt).digest("hex");
        if ( salted_password !== results.password ) {
            return callback({ "success": false, "message": 'Incorrect password.' });
        }
        user = results;
        user.id = +user.id;
        delete user.salt;
        callback({ "success": true, "message": 'Logged in', "user": user });
    });
}
exports.getUser = function( id, callback ) {
    connection.query(`SELECT * from  users where id = ?`,[ id ], ( err, results ) => {
        if ( err ) return callback({ "success": false, "message": err.sqlMessage });
        if ( !results[0] ) return callback({ "success": false, "message": `No user found.` })
        results = results[0];
        results.id = +results.id;
        delete results.salt;
        callback({ "success": true, "user": results });
    });
}
exports.getUserByEmail = function( email, callback ) {
    connection.query(`SELECT * from  users where email = ?`,[ email ], ( err, results ) => {
        if ( err ) return callback({ "success": false, "message": err.sqlMessage });
        if ( !results[0] ) return callback({ "success": false, "message": `No user found.` })
        results = results[0];
        results.id = +results.id;
        delete results.salt;
        callback({ "success": true, "user": results });
    });
}
exports.getNewSaltedPassword = function( user, callback ) {
    connection.query(`SELECT * from  users where email = ?`,[ user.email ], ( err, results ) => {
        if ( err ) return callback({ "success": false, "message": err.sqlMessage });
        if ( !results[0] ) return callback({ "success": false, "message": `No user found.` })
        results = results[0];
        results.id = +results.id;
        results.salted_password = crypto.createHash("sha256").update(user.password + results.salt).digest("hex");
        delete results.salt;
        callback({ "success": true, "user": results });
    });
}

exports.setNewSaltedPassword = function( user, callback ) {
    connection.query(`UPDATE users set password = ? where id = ?`,[ user.password, user.id ], ( err, results ) => {
        if ( err ) return callback({ "success": false, "message": err.sqlMessage });
        callback({ "success": true, "message": "Password updated." });
    });
}