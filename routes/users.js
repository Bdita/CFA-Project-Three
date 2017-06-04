const express = require('express');
const router = express.Router();
const User = require('../models/user');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

// Register
router.get('/register', function(req, res) {
  res.render('register');
});
// login
router.get('/login', function(req, res) {
  res.render('login');
});
// register user
router.post('/register', function(req, res) {
  const name = req.body.name;
  const email = req.body.email;
  const password = req.body.password;
  const password2 = req.body.password2;

  // console.log(name);
  // console.log(email);
  // console.log(password);
  // console.log(password2);
  req.checkBody('name', 'Name is required').notEmpty();
  req.checkBody('email', 'Email is required').notEmpty();
  req.checkBody('email', 'Email is not valid').isEmail();
  req.checkBody('password', 'Password is required').notEmpty();
  req.checkBody('password2', 'This field cannot be blank').notEmpty();
  req.checkBody('password2', 'Passwords do not match').equals(req.body.password);

  const errors = req.validationErrors();

  if (errors){
    res.render('register', {
      errors:errors
    });
  }else{
      const newUser = new User({
        companyname: name,
        email: email,
        password: password
      });
      User.createUser(newUser, (err, user) => {
        if (err) throw err;
        console.log(user);
      });
      req.flash('success_msg', 'You are registered and can now login');

      res.redirect('/users/login');
    }

});

passport.use(new LocalStrategy({
    usernameField : 'email',
    passwordField : 'password',
    },

  function(email, password, done) {
    User.getUserByEmail(email, (err, user) => {
      if (err) throw err;
      if(!user){
        return done(null, false, {message: 'Unknown User'});
      }

      User.comparePassword(password, user.password, (err, isMatch) => {
        if (err) throw err;
        if (isMatch) {
          return done(null, user);
        } else {
          // If password does not match, no handshake with passport
          done(null, false, { message: 'Incorrect password' });
        }
      });
    });
  }));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});

router.post('/login',
  passport.authenticate('local', {successRedirect: '/', failureRedirect: '/users/login', failureFlash: true}),
  function(req, res) {
    res.redirect('/');
  });

router.get('/logout', function(req, res) {
  req.logout();
  req.flash('success_msg', 'You are logged out.');
  res.redirect('/users/login');
});


module.exports = router;
