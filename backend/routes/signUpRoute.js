// User Register/Signup Form API

const {
  postUserSignup,
  verifyEmail,
  resendOtpCode,
} = require('../controller/signUpController')

const express = require('express')
const signUpRouter = express.Router()

signUpRouter.route('/').post(postUserSignup)


module.exports = signUpRouter
