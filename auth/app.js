const express = require('express');
const mongoose = require('mongoose');
const authRoutes = require('./routes/auth-routes');
const HttpError = require('./models/HttpError');

const app = express();

app.use(express.json());

//CORS
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers','Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.setHeader('Access-Control-Allow-Methods','OPTIONS, PUT, PATCH, POST, DELETE, GET');
    next();
  });

app.use('/api/auth', authRoutes);

app.use((req,res,next)=>{
    throw new HttpError('Unable to find method / route', 404)
})

app.use((error,req,res,next)=>{
    if(res.headerSent) {
        return next(error);
    }
    res.status(error.code || 500).json({message: error.message || 'An error occured, try again'});
})

mongoose.connect(process.env.MONGO_URI)
.then(()=>{
    console.log('Connected to DB');
    app.listen(5000);
}).catch(error=>{
    console.log(error)
})

module.exports = app;