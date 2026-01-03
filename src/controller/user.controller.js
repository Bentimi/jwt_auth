const User = require("../models/user.models");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require('dotenv').config();
const sendEmail = require("../config/email");
const { sendWelcomeEmail, sendLoginNotification } = require("../utilis/emailService");

const   signup = async (req, res) => {
    const { name, email, password } = req.body;

    try {
        if(!name || !email || !password) {
            return res.status(400).json({message: 'All fields are required'});
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({message: 'User already exists'});
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpexpiry = new Date(Date.now() + 10 * 60 * 1000);

    

        const newuser = new User({
            name,
            email,
            password: hashedPassword,
            otp,
            otpexpiry
        })

        await newuser.save();

        // await sendEmail(
        //     email,
        //     'Verify your account',
        //     `Your OTP for account verification is ${otp}. It will expire in 10 minutes.`
        // )

        await sendWelcomeEmail({ 
            email, 
            name,
            loginUrl: process.env.LOGIN_URL
            }).catch(err => console.error('Welcome email failed:', err));

        return res.status(201).json({message: 'User created successfully'});
    } catch (e) {
        console.error('Error during singup', e);
        return res.status(500).json({message: 'Internal server errror'});
    }
}

const login = async (req, res) => {
    const { email, password } = req.body;
    try {
        if (!email || !password) {
            return res.status(400).json({message: 'All fields are required!'});
        }

        const user = await User.findOne({ email });
        if (!user){
            return res.status(404).json({message: 'User not found'});
        }

        if (!user.isVerified) {
            return res.status(401).json({message: 'User not verified, please verify your account'});
        }

        const comparePassword = await bcrypt.compare(password, user.password);

        if (!comparePassword) {
            return res.status(401).json({message: 'Invalid Credentials'});
        }

        const token = await jwt.sign({ userId: user._id, email: user.email, name: user.name }, process.env.JWT_SECRET,
            {
                expiresIn: "1h",
            }
        )

        user.otp = null;
        await user.save();

        await sendLoginNotification({
        email: user.email,
        name: user.name,
        location: req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'Unknown',
        device: req.headers['user-agent'] || 'Web Browser',
        resetPasswordUrl: process.env.FORGOT_PASSWORD_URL
        })

        return res.status(200).json({message: 'Login successful', token});
 
    } catch (e) {
        console.error('Error during login', e);
        return res.status(500).json({message: 'Internal Server Error'});
    }
};

const forgetPassword = async (req, res) => {
    const { email } = req.body;

    try{
        const user = await User.findOne({ email });
    
        if (!user) {
            return res.status(401).json({message: 'User not found'});
        }
        const otp = Math.floor(100000 + Math.random() * 90000).toString();
        const otpexpiry = new Date(Date.now() + 10 * 60 * 1000);
        user.otp = otp;
        user.otpexpiry = otpexpiry;
        await user.save();

        // await sendEmail(
        //     email,
        //     'Reset your password',
        //     `Your OTP for password reset is ${otp}. It will expire in 10 minutes.`
        // )


        const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:8000'}/reset-password?token=${resetToken}`;
        sendPasswordResetEmail({
        email: user.email,
        name: user.name,
        resetToken,
        resetUrl,
        expiryTime: '1 hour'
        })

        return res.status(200).json({message: 'Forgotten Password, OTP expires in 10 minutes', otp})
        
    } catch (e) {
        console.error('Error during forget password', e)
        return res.status(500).json({message: 'Internal server error'});
    }
}

const resetPassword = async (req, res) => {
    const { otp, password } = req.body;
    try{
        if (!otp || !password) {
            return res.status(400).json({message: 'All fields are required'});
        }
        if (!otp) {
             return res.status(400).json({message: 'OTP is required'});
        }

        const user = await User.findOne({ otp });

        if (!user) {
             return res.status(404).json({message: 'invalid OTP'});
        }

        if (user.otpexpiry < new Date()) {
             return res.status(400).json({message: 'OTP has expired'});
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        user.password = hashedPassword;
        user.otp = null;

        await user.save();
        return res.status(200).json({message: 'Password reset successful'});

    } catch (e) {
        console.error('Error during reset password', e)
        return res.status(500).json({message: 'Internal server error'});
    }
}

const verifyOtp = async (req, res) => {
    const { otp } = req.body;

    try {
        if ( !otp ) {
            return res.status(400).json({message: 'OTP is required'});
        }

        const user = await User.findOne({ otp });
        if( !user ){
            return res.status(404).json({message: 'Invalid OTP'});
        }
        if ( user.otpexpiry < new Date() ) {
            return res.status(400).json({message: 'OTP has expired'});
        }

        user.isVerified = true;
        user.otp = null;
        user.otpexpiry = null;
        await user.save();
        return res.status(200).json({message: 'User verified successfully'});

    } catch (e) {
        console.error('Error during OTP verification', e);
        return res.status(500).json({message: 'Internal server error'});
    }
}

const resendOtp = async (req, res) => {
    const { email } = req.body;
    try { 
        if (!email) {
            return res.status(400).json({ message: "Email is required" });
        }

        const user  = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: "User not found" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpexpiry = new Date(Date.now() + 10 * 60 * 1000);

        user.otp = otp
        user.otpexpiry = otpexpiry

        await user.save()
        return res.status(200).json({ message: "OTP sent successfully", otp: otp })

    } catch (e) {
        console.error('Error sending OTP');
        return res.status(500).json({ message: "Internal server error" });
    }
}

const getAllUsers = async (req, res) => {

    const { userId } = req.user;

    try {
        const adminuser = await User.findById(userId);
        if (adminuser.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied' });
        }

        const users = await User.find().select('-password -otp -otpexpiry');
        return res.status(200).json({ users });
    } catch (e) {
        console.error('Error fetching users', e);
        return res.status(500).json({ message: 'Internal server error' });
    }
}

module.exports = { signup, login, forgetPassword, resetPassword, verifyOtp, resendOtp, getAllUsers };