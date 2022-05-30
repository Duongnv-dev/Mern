const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const auth = require('../../middleware/auth');
const User = require('../../models/User');
const { check, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const config = require('config');
const secret = config.get('jwtSecret');

// @route   GET api/auth
// @desc    Test Route
// @access  Public

router.get('/', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// @route   Post api/login
// @desc    Authenticat user & get token
// @access  Public

router.post('/login', [
    check('email', 'Please enter a valid email address ').isEmail(),
    check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6})
], async (req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(400).json({errors: errors.array()});
    }

    const { email, password } = req.body;

    try {
        // Check user in db
        let user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ errors: [{ msg: 'Invalid Credentials' }] });
        }

        // Validate password
        
        const isMatch = await bcrypt.compare(password, user.password)

        if (!isMatch) {
            return res.status(404).json({ errors: [{ msg: 'Invalid Password' }]});
        }

        // Return jsonwebtoken

        const payload = {
            user: {
                id: user.id,
            }
        }
        jwt.sign(
            payload,
            secret,
            { expiresIn: 360000},
            (err, token) => {
                if (err) throw err;
                res.json({token: token});
            }
        );

        // res.send('User Route');

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Sever Error');
    }

})

module.exports = router;
