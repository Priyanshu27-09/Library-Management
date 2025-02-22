const UserModel = require('../models/signUpModel');
const bcrypt = require('bcrypt');

const postUserSignup = async (req, res) => {
  const { username, email, phone, userType, password } = req.body;

  // Alphanumeric password validation with Special character
  const alphanumericRegex = /^(?=.*[a-zA-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/;

  if (!password.match(alphanumericRegex)) {
    return res.status(400).json({
      success: false,
      message: 'Password must be alphanumeric and contain at least one special character.',
    });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  // Check if user already registered
  const checkPrevUser = await UserModel.findOne({ email }).select('-password');

  if (!checkPrevUser) {
    await UserModel.create({
      username,
      email,
      password: hashedPassword,
      phone,
      userType,
      emailVerified: true, // Automatically setting email as verified
    });

    return res.status(200).json({
      success: true,
      message: 'Signup successful. You can now log in.',
    });
  }

  return res.status(200).json({
    success: false,
    message: 'Account already exists. Please log in.',
  });
};

module.exports = {
  postUserSignup,
};
