const nodemailer = require('nodemailer');
const ejs = require('ejs');
const path = require('path');
require('dotenv').config();

const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

transporter.verify((error, success) => {
    if (error) {
        console.error("Email transporter verification failed", error);
    } else {
        console.log("Email service is ready to send messages");
    }
});

const sendWelcomeEmail = async ({ email, name, loginUrl}) => {
    try {
        const templatePath = path.join(__dirname, '../../templates/emails/welcome.ejs');
        const html = await ejs.renderFile(templatePath, { name, email, loginUrl });

        const mailOptions = {
            from: `"${ process.env.EMAIL_FROM_NAME }" <${ process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Welcom to Big-B Studio',
            html,
        }


        const info = await transporter.sendMail(mailOptions);
        console.log('Welcome email sent: %s', info.messageId);
        return { success: true, messageId: info.messageId };
    } catch (error) {
        console.error('Failed tosend welcome email', error);
        throw error;
    }
};

const sendLoginNotification = async ({ email, name, location, device, resetPasswordUrl }) => {
    try {
        const templatePath = path.join(__dirname, '../../templates/emails/login-notification.ejs');
        const html = await ejs.renderFile(templatePath, { 
            name, 
            email, 
            location, 
            device, 
            resetPasswordUrl 
        });

        const mailOptions = {
            from: `${process.env.EMAIL_FROM_NAME} <${process.env.EMAIL_USER}>`,

            to: email,
            subject: 'New Login Detected - Security Alert',
            html,
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('Login notification email sent: %s', info.messageId);
    } catch (error) {
        console.error('Failed to send login notification', error);
        throw error;
    }
};

const sendPasswordResetEmail = async ({ email, name, resetToken, resetUrl, expiryTime }) => {
    try {
        const templatePath = path.join(__dirname, '../../templates/emails/forgot-password.ejs');
        const html = await ejs.renderFile(templatePath, { 
            name, 
            email, 
            resetToken, 
            resetUrl, 
            expiryTime 
        });

        const mailOptions = {
            from: `"${process.env.EMAIL_FROM_NAME || 'TechyJaunt Academy'}" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Password Reset Request - Action Required',
            html,
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('✉️ Password reset email sent:', info.messageId);
        return { success: true, messageId: info.messageId };
    } catch (error) {
        console.error('Failed to send password reset email:', error);
        throw error;
    }
};

const sendPasswordResetSuccessEmail = async ({ email, name, location, loginUrl}) => {
    try {
        const templatePath = path.join(__dirname, '../../templates/emails/password-reset-success.ejs');
        const html = await ejs.renderFile(templatePath, { 
            name, 
            email, 
            location, 
            loginUrl 
        });

        const mailOptions = {
            from:  `${process.env.EMAIL_FROM_NAME} <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Password Reset Successful',
            html,
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('Password reset success email sent: %s', info.messageId);
    } catch (error) {
        console.error('Failed to send password reset success email', error);
        throw error;

    }
}

module.exports = {
    sendWelcomeEmail,
    sendLoginNotification,
    sendPasswordResetEmail,
    sendPasswordResetSuccessEmail
}