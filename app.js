const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const mongoose = require('mongoose');
const passport = require('passport');
const flash = require('connect-flash');
const session = require('express-session');

// const cookieParser = require('cookie-parser');
// const csrf = require('csurf');
// const bodyParser = require('body-parser');

const app = express();

// Passport Config
require('./config/passport')(passport);

// DB Config
mongoose.connect('mongodb://localhost/passport-tutorial');
mongoose.set('debug', true);

// EJS
app.use(expressLayouts);
app.set('view engine', 'ejs');

// // setup route middlewares
// const csrfProtection = csrf({ cookie: true });
// const parseForm = bodyParser.urlencoded({ extended: false });
//
// // Express body parser
// app.use(express.urlencoded({ extended: true }));
//
// // parse cookies
// // we need this because "cookie" is true in csrfProtection
// app.use(cookieParser());

// Express session
app.use(
  session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true
  })
);

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Connect flash
app.use(flash());

// Global variables
app.use(function(req, res, next) {
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  res.locals.error = req.flash('error');
  next();
});

// Routes
app.use('/', require('./routes/index.js'));
app.use('/users', require('./routes/users.js'));

const PORT = process.env.PORT || 5000;

app.listen(PORT, console.log(`Server started on port ${PORT}`));
