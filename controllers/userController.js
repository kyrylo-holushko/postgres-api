const User = require('../models/userModel');
const email = require("email-validator");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodeoutlook = require('nodejs-nodemailer-outlook');
const dotenv = require('dotenv');
dotenv.config();
const { JWTSECRET, JWTEXPIRY, MAILPASSWORD } = process.env;

exports.signup = (req, res) => {
    const usernameRegEx = RegExp(/^[a-zA-Z0-9]{1,15}$/);
    if(!usernameRegEx.test(req.body.username))
        res.status(500).json({ message: "Username must be alphanumeric only and no more than 15 characters!"});
    else if(!email.validate(req.body.email))
        res.status(500).json({ message: "Email entered is not a valid email!"});
    else if(req.body.password!==req.body.passwordConfirmed)
        res.status(500).json({ message: "Passwords don't match, Account not created!"}); 
    else {
        let { passwordConfirmed, ...data } = req.body;
        bcrypt.hash(data.password, 10).then(hash=>{
            data.password = hash;
            User.createUser(data).then((result)=>{
                if(result instanceof Error)
                    throw result;
                else
                    sendConfirmation(result);
                    res.status(201).json({ message: 'New User Created', data: result});
            }).catch(e=>{console.log('Encryption Failed.')});
        }).catch(e=>{
            res.status(500).json({ message: e.message });
        });
    }
};

async function sendConfirmation(data) {
    await nodeoutlook.sendEmail({
        auth: {
            user: "demo-no-reply@outlook.com",
            pass: `${MAILPASSWORD}`
        },
        from: 'demo-no-reply@outlook.com',
        to: `${data.email}`,
        subject: 'Account Creation Confirmation',
        text: `Hello ${data.username}, your account has been successfully created!`,
        onError: (e) => console.log(e),
        onSuccess: (i) => console.log(i)
    });
};

exports.login = (req, res) => {
    const { usernameOrEmail, password } = req.body;
    let data;
    if(/@/.test(usernameOrEmail)){
        User.checkEmail(usernameOrEmail).then((result) => {
            if(result instanceof Error)
                throw result;
            else
                compareAndEncrypt(String(password), result, res);
        }).catch(e=>{
            res.status(500).json({ message: e.message });
        });
    }     
    else {
        User.checkUsername(usernameOrEmail).then((result) => {
            if(result instanceof Error)
                throw result;
            else
                compareAndEncrypt(String(password), result, res);
        }).catch(e=>{
            res.status(500).json({ message: e.message });
        });
    }
};

function compareAndEncrypt(password, data, res) {
    bcrypt.compare(password, data.password).then((result) => {
        if (result === true) {
            const token = signToken(data.uid, data.username, data.email);
            res.status(200).json({ message: 'Login successful', token: token });
        } else {
            res.status(500).json({ message: 'Could not log in. Passwords do not match!' });
        }
    });  
};

function signToken(uid, username, email){
    return jwt.sign({ uid, username, email }, JWTSECRET, { expiresIn: JWTEXPIRY });
};

exports.updateUser = (req, res) => {
    const usernameRegEx = RegExp(/^[a-zA-Z0-9]{1,15}$/);
    if(!usernameRegEx.test(req.body.username))
        res.status(500).json({ message: "Username must be alphanumeric only and no more than 15 characters!"});
    else if(!email.validate(req.body.email))
        res.status(500).json({ message: "Email entered is not a valid email!"});
    else {
        User.updateUser(req.userData.userID, req.userData.userEmail, req.body).then((result)=>{
            if(result instanceof Error){
                throw result;
            } else {
                const token = signToken(result.uid, result.username, result.email);
                res.status(200).json({ message: 'User has been updated!', token: token });
            }
        }).catch(e=>{res.status(500).json({ message: e.message })}); 
    }
};


exports.deleteUser = (req, res) => {
    User.deleteUser(req.userData.userID).then((result)=>{
        if(result instanceof Error)
            throw result;
        else
            res.status(200).json({ message: 'User has been Deleted!', data: result});
    }).catch(e=>{
        res.status(500).json({ message: `${e.message} User could not be deleted!` });
    });
};

exports.passwordLink = (req, res) => {
    if(!email.validate(req.body.email)) {
        res.status(500).json({ message: "Email entered is not a valid email!"});
    } else {
        User.checkEmail(req.body.email).then((result) => {
            if(result instanceof Error)
                throw result;
            else
                sendPasswordReset(result, req.body.email).then(()=>{
                    res.status(200).json({ message: "Password reset link sent, please check your email."});
                }).catch(e=>{throw e});
        }).catch(e=>{
            res.status(500).json({ message: e.message });
        });
    }
};

async function sendPasswordReset(data, email) {
 
    const resetToken = signToken(data.uid, data.username, data.email);
    
    User.storeResetToken(email, resetToken).then(()=>{
        
        const link = `http://localhost:3000/passwordReset?token=${resetToken}`;

        nodeoutlook.sendEmail({
            auth: {
                user: "demo-no-reply@outlook.com",
                pass: `${MAILPASSWORD}`
            },
            from: 'demo-no-reply@outlook.com',
            to: `${data.email}`,
            subject: 'Password Reset',
            html: `<p>Hello ${data.username}. Please click this link to reset your password:<br/><br/><a href="${link}">Reset Password</a></p>`,
            onError: (e) => console.log(e),
            onSuccess: (i) => console.log(i)
        });

    }).catch(e=>{
        throw e;
    });
    
};

exports.passwordNew = (req, res) => {
    const resetToken = req.headers.authorization.split(' ')[1];
    if(req.body.password!==req.body.passwordConfirmed)
        res.status(500).json({ message: "Passwords don't match, Account not created!"}); 
    else {
        bcrypt.hash(req.body.password, 10).then(hash=>{

            User.setNewPassword(hash, resetToken).then(()=>{
                res.status(200).json({ message: "Password has been reset." });
            }).catch(e=>{throw e});
            
        }).catch(e=>{
            res.status(500).json({ message: e.message });
        });

    }
};