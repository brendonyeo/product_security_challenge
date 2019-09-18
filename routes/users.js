const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

// Load User model
const User = require('../models/User');
const { forwardAuthenticated } = require('../config/auth');

const csrf = require('csurf');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

// parse cookies
// we need this because "cookie" is true in csrfProtection
router.use(cookieParser());

// Express body parser
router.use(express.urlencoded({ extended: true }));

// setup route middlewares
const csrfProtection = csrf({ cookie: true });
const parseForm = bodyParser.urlencoded({ extended: false });

// Login Page
router.get('/login', csrfProtection, forwardAuthenticated, (req, res) => res.render('login', { csrfToken: req.csrfToken() } ));

// Invalid Login Page
router.get('/login/invalid', csrfProtection, forwardAuthenticated, (req, res) => res.render('login-invalid', { csrfToken: req.csrfToken() } ));

// Login After Register Page
router.get('/registersuccess', csrfProtection, forwardAuthenticated, (req, res) => res.render('register-success', { csrfToken: req.csrfToken() } ));

// Login
router.post('/login', csrfProtection, (req, res, next) => {
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/users/login/invalid',
    failureFlash: true
  })(req, res, next);
});

// Register Page
router.get('/register', csrfProtection, forwardAuthenticated, (req, res) => res.render('register', { csrfToken: req.csrfToken() } ));

// Register
router.post('/register', csrfProtection, (req, res) => {
  const { email, password, password2 } = req.body;
  let errors = [];

  if (!email || !password || !password2) {
    errors.push({ msg: 'Please enter all fields' });
  }

  if (password != password2) {
    errors.push({ msg: 'Passwords do not match' });
  }

  if (password.length < 6) {
    errors.push({ msg: 'Password must be at least 6 characters' });
  }

  if (errors.length > 0) {
    // console.log(errors);
    res.render('register', {
      errors,
      email,
      password,
      password2,
      csrfToken: req.csrfToken()
    });
  } else {
    User.findOne({ email: email }).then(user => {
      if (user) {
        errors.push({ msg: 'Email already exists' });
        res.render('register', {
          errors,
          email,
          password,
          password2,
          csrfToken: req.csrfToken()
        });
      } else {
        const newUser = new User({
          email,
          password,
          active:true
        });

        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) throw err;
            newUser.password = hash;
            newUser
            .save()
            .then(user => {
              async function main() {
                // create reusable transporter object using the default SMTP transport
                let transporter = nodemailer.createTransport({
                  service: 'gmail',
                  host: 'smtp.gmail.com',
                  port: 587,
                  secure: false, // true for 465, false for other ports
                  auth: {
                    user: "yangxuan.zendesk@gmail.com",
                    pass: "---redacted---"
                  }
                });

                // send mail with defined transport object
                let info = await transporter.sendMail({
                  from: 'yangxuan.zendesk@gmail.com',
                  to: req.body.email,
                  subject: 'Zendesk Login - New account created',
                  // text: 'A new account has been created',
                  html: 'Thank you for creating a new account with us!' // </br></br>Not you? Click <a href="">here</a>.'
                });

                // console.log('Message sent: %s', req.body.email);
              }
              main().catch(err => console.log(err));
              res.redirect('/users/registersuccess');
            })
            .catch(err => console.log(err));
          });
        });
      }
    });
  }
});

// Forgot Password Page
router.get('/forgot', csrfProtection, forwardAuthenticated, (req, res) => res.render('forgot', { csrfToken: req.csrfToken() } ));

// Forgot Password Page
router.get('/forgot/invalid', csrfProtection, forwardAuthenticated, (req, res) => res.render('forgot-invalid', { csrfToken: req.csrfToken() } ));

// Password Reset Email Sent Page
router.get('/forgot/complete', forwardAuthenticated, (req, res) => res.render('forgot-complete'));

// Forgot Password
router.post('/forgot', csrfProtection, (req, res, next) => {
  User.findOne({ email: req.body.email }).then(user => {
    if (!user) {
      // req.flash('error', 'No account with that email address exists.');
      return res.redirect('/users/forgot/complete');
    }

    var token = crypto.randomBytes(20).toString('hex');

    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

    user.save().then(user => {
      async function main() {
        // create reusable transporter object using the default SMTP transport
        let transporter = nodemailer.createTransport({
          service: 'gmail',
          host: 'smtp.gmail.com',
          port: 587,
          secure: false, // true for 465, false for other ports
          auth: {
            user: "yangxuan.zendesk@gmail.com",
            pass: "---redacted---"
          }
        });

        // send mail with defined transport object
        let info = await transporter.sendMail({
          from: 'yangxuan.zendesk@gmail.com',
          to: user.email,
          subject: 'Zendesk Login - Password Reset',
          text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://' + req.headers.host + '/users/reset/' + token + '\n\n' +
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'
        });
      }
      main().catch(err => console.log(err));
      res.redirect('/users/forgot/complete');
    })
    .catch(err => console.log(err));
  });
})

// Reset Password
router.get('/reset/:token', csrfProtection, (req, res) => {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, (err, user) => {
    if (!user) {
      return res.redirect('/users/forgot/invalid');
    }
    res.render('reset', { resetToken: req.params.token, csrfToken: req.csrfToken() });
  });
});

// Forgot Password
router.post('/reset/:token', csrfProtection, (req, res, next) => {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }).then(user => {
    if (!user) {
      // req.flash('error', 'No account with that email address exists.');
      return res.redirect('/users/forgot/invalid');
    }

    const { password, password2 } = req.body;
    let errors = [];

    if (!password || !password2) {
      errors.push({ msg: 'Please enter all fields' });
    }

    if (password != password2) {
      errors.push({ msg: 'Passwords do not match' });
    }

    if (password.length < 6) {
      errors.push({ msg: 'Password must be at least 6 characters' });
    }

    if (errors.length > 0) {
      // console.log(errors);
      return res.render('reset', {
        errors,
        password,
        password2,
        resetToken: req.params.token,
        csrfToken: req.csrfToken()
      });
    }

    bcrypt.genSalt(10, (err, salt) => {
      bcrypt.hash(req.body.password, salt, (err, hash) => {
        if (err) throw err;
        user.password = hash;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        user.save().then(user => {
          async function main() {
            let transporter = nodemailer.createTransport({
              service: 'gmail',
              host: 'smtp.gmail.com',
              port: 587,
              secure: false, // true for 465, false for other ports
              auth: {
                user: "yangxuan.zendesk@gmail.com",
                pass: "---redacted---"
              }
            });

            var currentTime = new Date(Date.now()); // The 0 there is the key, which sets the date to the epoch

            let info = await transporter.sendMail({
              from: 'yangxuan.zendesk@gmail.com',
              to: 'yangxuan.zendesk@gmail.com',//user.email,
              subject: 'Zendesk Login - Password Reset Successful',
              text: 'Your password has been successfully reset on ' + currentTime + "."
            });
          }
          main().catch(err => console.log(err));
          res.redirect('/users/login');
        })
        .catch(err => console.log(err));
      })
    })
  });
})

// Logout
router.get('/logout', (req, res) => {
  req.logout();
  req.flash('success_msg', 'You are logged out');
  res.redirect('/users/login');
});

module.exports = router;
