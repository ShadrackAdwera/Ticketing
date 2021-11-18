const brypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const User = require('../models/User');
const HttpError = require('../models/HttpError');

const signUp = async(req,res,next) => {
    const error = validationResult(req);
    if(!error.isEmpty()) {
        return next(new HttpError('Invalid email or password',422));
    }
    const { name, email, password, role } = req.body;
    //check if email exists
    let foundEmail
    let hashedPassword
    let token
    try {
        foundEmail = await User.findOne({email},'-password').exec();
    } catch (error) {
        return next(new HttpError('Internal server error', 500));
    }
    if(foundEmail) {
        return next(new HttpError('This email exists in the DB, login instead',422));
    }
    //hash password
    try {
        hashedPassword = await bcrypt.hash(password, 12);
    } catch (error) {
        return next(new HttpError('An error occured, try again', 500));
    }
    //create user
    const user = new User({
        name, 
        email, 
        password: hashedPassword, 
        role, 
        ticketsAssiged: [], resetToken: null, tokenExpiration: undefined
    })
    //save user
    try {
        await user.save()
    } catch (error) {
        return next(new HttpError('Auth failed', 500));
    }
    //generate token
    try {
        token = jwt.sign({ id: user._id.toString(), email }, 'supersecretkey', { expiresIn: '1h' })
    } catch (error) {
        return next(new HttpError('Auth failed', 500));
    }
    res.status(201).json({message: 'Sign up successful', user: { id: user._id.toString(), email, token }})
}

const login = async(req,res,next) => {
    const error = validationResult(req);
    if(!error.isEmpty()) {
        return next(new HttpError('Invalid email or password',422));
    }
    const { email, password } = req.body;

    let foundUser
    let isPassword
    let token
    try {
        foundUser = await User.findOne({email},'-password').exec()
    } catch (error) {
        return next(new HttpError('An error occured, try again',500));
    }
    if(!foundUser) {
        return next(new HttpError('This user does not exist, sign up', 404));
    }
    //check password
    try {
        isPassword = await bcrypt.compare(password, foundUser.password);
    } catch (error) {
        return next(new HttpError('Auth failed', 500))
    }
    //generate token
    try {
        token = jwt.sign({id: foundUser._id.toString(), email: foundUser.email}, 'supersecretkey', { expiresIn: '1h' });
    } catch (error) {
        return next(new HttpError('Auth failed', 500));
    }
    res.status(200).json({message: 'Sign Up Successful', user: { id: foundUser._id.toString(), email, token }})
}

const generatePasswordResetLink = async(req,res,next) => {
    const error = validationResult(req);
    if(!error.isEmpty()) {
        return next(new HttpError('Invalid email or password',422));
    }
    const { email } = req.body;
    let foundUser;
    let tokenReset;

    try {
        foundUser = await User.findOne({email}, '-password').exec();
    } catch (error) {
        return next(new HttpError('An error occured, try again', 500));
    }
    
    try {
        tokenReset = brypto.randomBytes(64).toString('hex');
    } catch (error) {
        return next(new HttpError('An error occured, try again', 500));
    }
    const tokenExpirationDate = Date.now() + 3600000;

    foundUser.resetToken = tokenReset;
    foundUser.tokenExpiration = tokenExpirationDate;

    try {
        await foundUser.save();
    } catch (error) {
        return next(new HttpError('An error occured, try again',500));
    }
    //email user with the link for password reset.
    res.status(200).json({message: 'Check your email for a password reset link'});
}

const resetPassword = async(req,res,next) => {
    const { resetToken } = req.params;
    const { password, id } = req.body;
    if(!resetToken || resetToken.length<60) {
        return next(new HttpError('Invalid token',401));
    }

    let foundUser;
    let hashedPassword;
    try {
        foundUser = await User.findOne({resetToken, tokenExpiration: { $gt: Date.now() }, _id: id},'-password').exec();
    } catch (error) {
        return next(new HttpError('An error occured, try again',500));
    }
    if(!foundUser) {
        return next(new HttpError('Password reset failed, try again',500));
    }

    try {
        hashedPassword = await bcrypt.hash(password, 12);
    } catch (error) {
        return next(new HttpError('An error occured, try again',500));
    }
    foundUser.password = hashedPassword;
    foundUser.resetToken = undefined;
    foundUser.tokenExpiration = undefined;

    try {
        await foundUser.save();
    } catch (error) {
        return next(new HttpError('An error occured, try again', 500));
    }
    res.status(200).json({message: 'Password reset is successful'});
}

exports.signUp = signUp;
exports.login = login;
exports.generatePasswordResetLink = generatePasswordResetLink;
exports.resetPassword = resetPassword;
