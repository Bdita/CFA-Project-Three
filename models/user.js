const mongoose = require('mongoose');
// Bcrypt for hashing passwords
const bcrypt = require('bcryptjs');

//User schema
const UserSchema = mongoose.Schema({
  companyname: {
    type: String,
    index: true,
  },
  password: {
    type: String,
  },
  email: {
    type: String,
    index: true,
  }
});

// Allow access to User model outside of this file
const User = module.exports = mongoose.model('User', UserSchema);

// Function to create a new user
module.exports.createUser = (newUser, callback) => {
  // Code from Bcrypt docs to hash password
  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(newUser.password, salt, (err, hash) => {
      newUser.password = hash;
      newUser.save(callback);
    });
  });
};

module.exports.getUserByEmail = (email, callback) => {
  const query = {email: email};
  User.findOne(query, callback);
}

module.exports.getUserById = (id, callback) => {
  User.findById(id, callback);
}

module.exports.comparePassword = (candidatePassword, hash, callback) => {
  bcrypt.compare(candidatePassword, hash, (err, isMatch) => {
    if (err) throw err;
    callback(null, isMatch);
  })
}
