const express = require('express');
const home = express.Router();
const users = require("../models/users.model");
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');

require('dotenv').config();

// Email transporter configuration
const transporter = nodemailer.createTransport({
    secure: true,
    host: 'smtp.gmail.com', 
    port: 465,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Password reset route
home.post("/forget-password", async (req, res) => {
    try {
        const { username } = req.body;

        // Check if the user exists
        const user = await users.findOne({ username });
        if (!user) {
            return res.status(404).json({
                message: "User not found",
                success: false
            });
        }

        // Generate token and expiry
        const token = crypto.randomBytes(20).toString('hex');
        const expires = Date.now() + 3600000; // Token valid for 1 hour

        // Update user in the database
        user.resetpasswordtoken = token;
        user.resetpasswordexpires = expires;
        await user.save();

        // Email options
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email, // Ensure user has a valid email
            subject: 'Password Reset',
            text: `Hello, ${user.username}. You requested a password reset. Use the following token to reset your password: ${token}. This token will expire in one hour.`
        };
        console.log("Mail Options:", mailOptions);

        // Send the email
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return res.status(500).json({
                    message: 'Failed to send email',
                    success: false,
                    error: error.message
                });
            }

            // Successful response (for testing only: remove token in production)
            return res.status(200).json({
                message: "Password reset email sent successfully",
                success: true,
                token: token, 
                expires
            });
        });
    } catch (error) {
        res.status(503).json({
            message: "Something went wrong on the server side",
            success: false,
            error: error.message
        });
    }
});


// Token verification route
home.get("/verify-token/:token", async (req, res) => {
    try {
        const { token } = req.params;

        // Check if the token exists in the database
        const user = await users.findOne({
            resetpasswordtoken: token,
            resetpasswordexpires: { $gt: Date.now() } // Ensure token is not expired
        });

        if (!user) {
            return res.status(400).json({
                message: "Invalid or expired token",
                success: false
            });
        }

        // Token is valid
        res.status(200).json({
            message: "Token is valid",
            success: true
        });

    } catch (error) {
        res.status(500).json({
            message: "Something went wrong on the server side",
            success: false,
            error: error.message
        });
    }
});

// Password reset route
home.post("/reset-password", async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        // Check if the token is valid and not expired
        const user = await users.findOne({
            resetpasswordtoken: token,
            resetpasswordexpires: { $gt: Date.now() } // Token should not be expired
        });

        if (!user) {
            return res.status(400).json({
                message: "Invalid or expired token",
                success: false
            });
        }

        // Hash the new password before saving it
        const saltRounds = 10;
        user.password = await bcrypt.hash(newPassword, saltRounds); // Hash the password

        // Clear the token and expiry after password reset
        user.resetpasswordtoken = undefined;
        user.resetpasswordexpires = undefined;

        await user.save();

        // Return success response
        res.status(200).json({
            message: "Password successfully reset",
            success: true
        });

    } catch (error) {
        res.status(500).json({
            message: "Something went wrong on the server side",
            success: false,
            error: error.message
        });
    }
});

module.exports = home;
module.exports = home;
