const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');

const router = express.Router();

router.post(
  '/signup',
  [
    body('fullName').not().isEmpty().withMessage('Full Name is required'),
    body('email').isEmail().withMessage('Please enter a valid email address'),
    body('phone')
      .isMobilePhone()
      .withMessage('Please enter a valid phone number'),
    body('password')
      .isLength({ min: 6 })
      .withMessage('Password must be at least 6 characters long'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { fullName, email, phone, password } = req.body;

    try {
      let user = await User.findOne({ email });
      if (user) {
        return res.status(400).json({ msg: 'User already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      user = new User({
        fullName,
        email,
        phone,
        password: hashedPassword,
      });

      await user.save();
      res.status(201).json({ msg: 'User created successfully' });
    } catch (error) {
      console.error(error.message);
      res.status(500).send('Server Error');
    }
  }
);

module.exports = router;
