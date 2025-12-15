const express = require('express');
const router =  express.Router();


const { signup, login, forgetPassword, resetPassword } = require('../controller/user.controller');

router.post('/signUp', signup);
router.post('/signIn', login);
router.put('/forget-password', forgetPassword);
router.post('/reset-password', resetPassword);


module.exports = router;