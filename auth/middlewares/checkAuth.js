const jwt = require('jsonwebtoken');
const HttpError = require('../models/HttpError');

const checkAuth = (req,res,next) => {
    if(req.method==='OPTIONS') {
        return next()
    }
    let decodedToken;
    const tkn = req.headers.get('Authorization');
    if(!tkn) {
        return next(new HttpError('Auth failed',401));
    }
    const token = tkn.split(' ')[1];
    if(!token) {
        return next(new HttpError('Auth failed', 401));
    }

    try {
        decodedToken = jwt.verify(token, 'supersecretkey');
        req.userData = { userId: decodedToken.id, email: decodedToken.email }
        next();
    } catch (error) {
        return next(new HttpError('An error occured, try again', 500));
    }
}

module.exports = checkAuth;