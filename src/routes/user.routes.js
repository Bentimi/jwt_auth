const express = require('express');
const router =  express.Router();
const isAuth = require('../config/auth');


const { signup, login, forgetPassword, resetPassword, verifyOtp, resendOtp, getAllUsers } = require('../controller/user.controller');

router.post('/signUp', signup);
router.post('/signIn', login);
router.put('/forget-password', forgetPassword);
router.post('/reset-password', resetPassword);
router.put('/verify-otp', verifyOtp);
router.post('/resend-otp', resendOtp);
router.get('/get-all-users', isAuth, getAllUsers);


module.exports = router;