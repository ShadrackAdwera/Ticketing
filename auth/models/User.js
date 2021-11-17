const mongoose = require('mongoose');
const { Schema } = mongoose;

const userSchema = new Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true, minlength: 6 },
    role: { type: String, required: true },
    ticketsAssiged: [ { type: Schema.Types.ObjectId } ],
    resetToken: { type: String },
    tokenExpiration: { type: Date }
}, { timestamps: true })

module.exports = mongoose.model('User', userSchema);