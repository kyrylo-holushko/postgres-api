const User = require('../models/userModel');
const email = require("email-validator");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();
const { JWTSECRET, JWTEXPIRY } = process.env;

exports.signup = (req, res) => {
    const usernameRegEx = RegExp(/^[a-zA-Z0-9]{1,15}$/);
    if(!usernameRegEx.test(req.body.username))
        res.status(500).json({ message: "Username must be alphanumeric only and no more than 15 characters!"});
    else if(!email.validate(req.body.email))
        res.status(500).json({ message: "Email entered is not a valid email!"});
    else if(req.body.password!==req.body.passwordConfirmed)
        res.status(500).json({ message: "Passwords don't match, Account not created!"}) 
    else {
        let { passwordConfirmed, ...data } = req.body;
        bcrypt.hash(data.password, 10).then(hash=>{data.password = hash;}).catch(e=>{console.log('Encryption Failed.')});
        User.createUser(data).then((result)=>{
            if(result instanceof Error)
                throw result;
            else
                res.status(201).json({ message: 'New User Created', data: result});
        }).catch(e=>{
            res.status(500).json({ message: e.message });
        });
    }
};

exports.login = (req, res) => {
    const { usernameOrEmail, password } = req.body;
    let data;
    if(/@/.test(usernameOrEmail)){
        User.checkEmail(usernameOrEmail).then((result) => {
            if(result instanceof Error)
                throw result;
            else
                compareAndEncrypt(password, result, res);
        }).catch(e=>{
            res.status(500).json({ message: e.message });
        });
    }     
    else {
        User.checkUsername(usernameOrEmail).then((result) => {
            if(result instanceof Error)
                throw result;
            else
                compareAndEncrypt(password, result, res);
        }).catch(e=>{
            res.status(500).json({ message: e.message });
        });
    }
};

function compareAndEncrypt(password, data, res) {
    bcrypt.compare(password, data.password).then((result) => {
        if (result === true) {
            const payload = { uid: data.uid, username: data.username };
            const token = jwt.sign(payload, JWTSECRET, { expiresIn: JWTEXPIRY });
            res.json({ message: 'login successful', token: token });
        } else {
            res.json({ message: 'Could not log in. Passwords do not match!' });
        }
    });  
};

exports.updateUser = (req, res) => {
    const usernameRegEx = RegExp(/^[a-zA-Z0-9]{1,15}$/);
    if(!usernameRegEx.test(req.body.username))
        res.status(500).json({ message: "Username must be alphanumeric only and no more than 15 characters!"});
    else if(!email.validate(req.body.email))
        res.status(500).json({ message: "Email entered is not a valid email!"});
    else if(req.body.password!==req.body.passwordConfirmed)
        res.status(500).json({ message: "Passwords don't match, Account not created!"}) 
    else {
        let { passwordConfirmed, ...data } = req.body;
        bcrypt.hash(data.password, 10).then(hash=>{data.password = hash;}).catch(e=>{console.log('Encryption Failed.')});
        User.updateUser(req.userData.userID, data).then((result)=>{
            if(result instanceof Error)
                throw result;
            else
                res.status(201).json({ message: 'User has been updated!', data: result});
        }).catch(e=>{
            res.status(500).json({ message: e.message });
        });
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