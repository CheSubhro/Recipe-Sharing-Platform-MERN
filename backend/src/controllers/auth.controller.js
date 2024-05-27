
import { asyncHandler } from '../utils/AsyncHandler.js'
import { ApiError } from '../utils/ApiError.js'
import HttpStatus from '../utils/HttpStatus.js'
import { ApiResponse } from '../utils/ApiResponse.js'
import bcrypt from 'bcrypt'
import { User } from '../models/user.model.js'
import jwt from "jsonwebtoken"


import sendEmailVerificationOTP from '../utils/sendEmailVerificationOTP.js';
import { EmailVerificationModel } from '../models/emailVerification.model.js';
import generateTokens from '../utils/generateTokens.js';
import setTokensCookies from '../utils/setTokensCookies.js';
import refreshAccessToken from '../utils/refreshAccessToken.js';
import { UserRefreshTokenModel } from '../models/userRefreshToken.model.js';
import transporter from '../config/emailConfig.js';


// User Email Register
const registerUser = asyncHandler ( async (req,res) =>{

    // TODO:
    // get user details from frontend
    // validation - not empty
    // check if user already exists: username, email
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res

    try {
        // Extract request body parameters
        const { name, email, password, password_confirmation } = req.body;
  
        // Check if all required fields are provided
        if (!name || !email || !password || !password_confirmation) {
          return res.status(400).json({ status: "failed", message: "All fields are required" });
        }
  
        // Check if password and password_confirmation match
        if (password !== password_confirmation) {
          return res.status(400).json({ status: "failed", message: "Password and Confirm Password don't match" });
        }
  
        // Check if email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
          return res.status(409).json({ status: "failed", message: "Email already exists" });
        }
  
        // Generate salt and hash password
        const salt = await bcrypt.genSalt(Number(process.env.SALT));
        const hashedPassword = await bcrypt.hash(password, salt);
  
        // Create new user
        const newUser = await new User({ name, email, password: hashedPassword }).save();
  
        sendEmailVerificationOTP(req, newUser)
  
        // Send success response
        res.status(201).json({
          status: "success",
          message: "Registration Success",
          user: { id: newUser._id, email: newUser.email }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ status: "failed", message: "Unable to Register, please try again later" });
    }

})

// User Email Verification
const verifyEmail = asyncHandler ( async (req,res) =>{

    try {

        // Extract request body parameters
        const { email, otp } = req.body;
  
        // Check if all required fields are provided
        if (!email || !otp) {
          return res.status(400).json({ status: "failed", message: "All fields are required" });
        }
  
        const existingUser = await User.findOne({ email });
  
        // Check if email doesn't exists
        if (!existingUser) {
          return res.status(404).json({ status: "failed", message: "Email doesn't exists" });
        }
  
        // Check if email is already verified
        if (existingUser.is_verified) {
          return res.status(400).json({ status: "failed", message: "Email is already verified" });
        }
  
        // Check if there is a matching email verification OTP
        const emailVerification = await EmailVerificationModel.findOne({ userId: existingUser._id, otp });
        if (!emailVerification) {
          if (!existingUser.is_verified) {
            // console.log(existingUser);
            await sendEmailVerificationOTP(req, existingUser);
            return res.status(400).json({ status: "failed", message: "Invalid OTP, new OTP sent to your email" });
          }
          return res.status(400).json({ status: "failed", message: "Invalid OTP" });
        }
  
        // Check if OTP is expired
        const currentTime = new Date();
        // 15 * 60 * 1000 calculates the expiration period in milliseconds(15 minutes).
        const expirationTime = new Date(emailVerification.createdAt.getTime() + 15 * 60 * 1000);
        if (currentTime > expirationTime) {
          // OTP expired, send new OTP
          await sendEmailVerificationOTP(req, existingUser);
          return res.status(400).json({ status: "failed", message: "OTP expired, new OTP sent to your email" });
        }
  
        // OTP is valid and not expired, mark email as verified
        existingUser.is_verified = true;
        await existingUser.save();
  
        // Delete email verification document
        await EmailVerificationModel.deleteMany({ userId: existingUser._id });
        return res.status(200).json({ status: "success", message: "Email verified successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ status: "failed", message: "Unable to verify email, please try again later" });
    }
})    

// User Login
const loginUser = asyncHandler ( async (req,res) =>{

    // TODO:
    // get user details from frontend
    // validation - not empty
    // Check if the password is correct
    // Generate JWT token
    // return res
    try {
        const { email, password } = req.body
        // Check if email and password are provided
        if (!email || !password) {
          return res.status(400).json({ status: "failed", message: "Email and password are required" });
        }
        // Find user by email
        const user = await User.findOne({ email });
  
        // Check if user exists
        if (!user) {
          return res.status(404).json({ status: "failed", message: "Invalid Email or Password" });
        }
  
        // Check if user verified
        if (!user.is_verified) {
          return res.status(401).json({ status: "failed", message: "Your account is not verified" });
        }
  
        // Compare passwords / Check Password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return res.status(401).json({ status: "failed", message: "Invalid email or password" });
        }
  
        // Generate tokens
        const { accessToken, refreshToken, accessTokenExp, refreshTokenExp } = await generateTokens(user)
  
        // Set Cookies
        setTokensCookies(res, accessToken, refreshToken, accessTokenExp, refreshTokenExp)
  
        // Send success response with tokens
        res.status(200).json({
          user: { id: user._id, email: user.email, name: user.name, roles: user.roles[0] },
          status: "success",
          message: "Login successful",
          access_token: accessToken,
          refresh_token: refreshToken,
          access_token_exp: accessTokenExp,
          is_auth: true
        });
  
  
      } catch (error) {
        console.error(error);
        res.status(500).json({ status: "failed", message: "Unable to login, please try again later" });
      }

})

// Get New Access Token OR Refresh Token
const getNewAccessToken = asyncHandler ( async (req,res) =>{

    try {
        // Get new access token using Refresh Token
        const { newAccessToken, newRefreshToken, newAccessTokenExp, newRefreshTokenExp } = await refreshAccessToken(req, res)
  
        // Set New Tokens to Cookie
        setTokensCookies(res, newAccessToken, newRefreshToken, newAccessTokenExp, newRefreshTokenExp)
  
        res.status(200).send({
          status: "success",
          message: "New tokens generated",
          access_token: newAccessToken,
          refresh_token: newRefreshToken,
          access_token_exp: newAccessTokenExp
        });
  
    } catch (error) {
        console.error(error);
        res.status(500).json({ status: "failed", message: "Unable to generate new token, please try again later" });
    }   

})





export {
    registerUser,
    verifyEmail,
    loginUser,
    getNewAccessToken
}