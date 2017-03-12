const passport = require('passport');
const User = require('../models/user')
const config = require('../config')
const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt
const LocalStrategy = require('passport-local')

// Create local Strategy
const localOptions = { usernameField: 'email' }
const localLogin = new LocalStrategy(localOptions, (email, password, done) => {
  // verify email and password, call done w/ user if correct info
  // otherwise call done w/ false
  User.findOne({ email: email }, (err, user) => {
    if (err) { return done(err) }
    if (!user) { return done(null, false) }

    // compare passwords
    user.comparePassword(password, (err, isMatch) => {
      if (err) { return done(err) }
      if (!isMatch) { return done(null, false) }

      return done(null, user)
    })
  })
})

// setup options for jwt Strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
}

// create jwt Strategy
const jwtLogin = new JwtStrategy(jwtOptions, (payload, done) => {
  // see if the user ID in payload exists in db
  // if so, call done with user object
  // else call done without a user object
  User.findById(payload.sub, (err, user) => {
    if (err) { return done(err, false) }

    if (user) {
      done(null, user)
    } else {
      done(null, false)
    }
  })
})

// tell passport to use this Strategy
passport.use(jwtLogin)
passport.use(localLogin)
