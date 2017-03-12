const jwt = require('jwt-simple')
const User = require('../models/user')
const config = require('../config')

function tokenForUser(user) {
  const timestamp = new Date().getTime()
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret)
}

exports.signin = (req, res, next) => {
  // user has had email & pwd auth'd
  // need to return a token
  res.send({ token: tokenForUser(req.user) })
}

exports.signup = (req, res, next) => {
  const email = req.body.email
  const password = req.body.password

  if (!email || !password) {
    return res.status(422).send({ error: 'You must provide email and password' })
  }
  // See if user with given email exists
  User.findOne({ email: email }, (err, existingUser) => {
    if (err) { return next(err) }

    // if exists, return an error
    if (existingUser) {
      return res.status(422).send({ error: 'Email is in use' })
    }

    // if !exists, create and save user record
    const user = new User({
      email: email,
      password: password
    })

    user.save((err) => {
      if (err) { return next(err) }

      // respond to req indicating user was created
      res.json({ token: tokenForUser(user) })
    })
  })
}
