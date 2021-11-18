const { body } = require('express-validator');
const express = require('express');
const mongoose = require('mongoose');
const { signUp, login, resetPassword, generatePasswordResetLink } = require('../controllers/auth-controllers');

const router = express.Router();

router.post('/sign-up',[
    body('name').trim().isLength({min: 3}),
    body('email').normalizeEmail().isEmail(),
    body('password').trim().isLength({min: 6})
],signUp)

router.post('/login',[
    body('email').normalizeEmail().isEmail(),
    body('password').trim().isLength({min: 6})
],login)

router.post('/request-reset-password',[
    body('email').normalizeEmail().isEmail()
],generatePasswordResetLink)

router.post('/reset-password/:resetToken',[
    body('id').not().isEmpty().custom(input=>mongoose.Types.ObjectId.isValid(input)),
    body('password').trim().isLength({min: 6})
],resetPassword)

module.exports = router;