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
        name, email, password: hashedPassword, role
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