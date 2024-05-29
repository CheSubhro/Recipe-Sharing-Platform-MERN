
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
const registerUser = asyncHandler(async (req, res, next) => {

    // TODO:
    // get user details from frontend
    // validation - not empty
	// Check if password and password_confirmation match
	// check if user already exists: email
	// password hasing 
    // create user object - create entry in db
    // check for user creation
    // return res

    try {
        // Extract request body parameters
        const { name, email, password, password_confirmation } = req.body;

        // Check if all required fields are provided
        if (!name || !email || !password || !password_confirmation) {

			throw new ApiError(HttpStatus.BAD_REQUEST, "All fields are required");
        }

        // Check if password and password_confirmation match
        if (password !== password_confirmation) {
          
			throw new ApiError(HttpStatus.BAD_REQUEST, "Password and Confirm Password don't match");
        }

        // Check if email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
          
			throw new ApiError(HttpStatus.CONFLICT, "Email already exists");
        }

        // Generate salt and hash password
        const salt = await bcrypt.genSalt(Number(process.env.SALT));
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user
        const newUser = await new User({ name, email, password: hashedPassword }).save();

        sendEmailVerificationOTP(req, newUser)

        // Send success response
        const apiResponse = new ApiResponse(HttpStatus.CREATED, 
			{
				user: { id: newUser._id, email: newUser.email }
			}, "Registration Success");
		res.status(HttpStatus.CREATED).json(apiResponse);
    } catch (error) {
        if (error instanceof ApiError) {
			res.status(error.statusCode).json({
			  status: "failed",
			  message: error.message,
			  errors: error.errors
			});
		} else {
			console.error(error);
			res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
			  status: "failed",
			  message: "Unable to Register, please try again later"
			});
		}
    }

})

// User Email Verification
const verifyEmail = asyncHandler(async (req, res, next) => {

	// TODO:
    // get email,otp from request body
    // validation - not empty
	// check if email exist or not
	// check if email already verified or not
	// check if there is a matching email verification OTP 
	// check if OTP is expired
	// if OTP expired, send new OTP
	// OTP is valid and not expired, mark email as verified
	// Delete email verification document
    // create user object - create entry in db
    // return res

    try {

        // Extract request body parameters
    	const { email, otp } = req.body;

        // Check if all required fields are provided
		if (!email || !otp) {

			throw new ApiError(HttpStatus.BAD_REQUEST, "All fields are required");
		}

        const existingUser = await User.findOne({ email });

        // Check if email doesn't exist
    	if (!existingUser) {

			throw new ApiError(HttpStatus.NOT_FOUND, "Email doesn't exist");
	  	}

        // Check if email is already verified
		if (existingUser.is_verified) {

			throw new ApiError(HttpStatus.BAD_REQUEST, "Email is already verified");
		}

        // Check if there is a matching email verification OTP
		const emailVerification = await EmailVerificationModel.findOne({ userId: existingUser._id, otp });

		if (!emailVerification) {
		if (!existingUser.is_verified) {
			
			await sendEmailVerificationOTP(req, existingUser);
			throw new ApiError(HttpStatus.BAD_REQUEST, "Invalid OTP, new OTP sent to your email");
		}
			throw new ApiError(HttpStatus.BAD_REQUEST, "Invalid OTP");
		}

        // Check if OTP is expired
		const currentTime = new Date();
		const expirationTime = new Date(emailVerification.createdAt.getTime() + 15 * 60 * 1000);
		if (currentTime > expirationTime) {
		// OTP expired, send new OTP
		await sendEmailVerificationOTP(req, existingUser);
			throw new ApiError(HttpStatus.BAD_REQUEST, "OTP expired, new OTP sent to your email");
		}

        // OTP is valid and not expired, mark email as verified
		existingUser.is_verified = true;
		await existingUser.save();

        // Delete email verification document
    	await EmailVerificationModel.deleteMany({ userId: existingUser._id });

        // Send success response
		const apiResponse = new ApiResponse(HttpStatus.OK, null, "Email verified successfully");
		res.status(HttpStatus.OK).json(apiResponse);
    } catch (error) {
        if (error instanceof ApiError) {
			res.status(error.statusCode).json({
			  status: "failed",
			  message: error.message,
			  errors: error.errors
			});
		} else {
			console.error(error);
			res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
			  status: "failed",
			  message: "Unable to verify email, please try again later"
			});
		}
    }
})

// User Login
const loginUser = asyncHandler(async (req, res, next) => {

    // TODO:
    // get email,password from request body
    // validation - not empty
	// check if email/user exist or not
	// check if email/user already verified or not
	// compare passwords / check Password
	// generate tokens
	// set Cookies
	// send success response with tokens
    // return res
    try {

        const { email, password } = req.body

        // Check if email and password are provided
        if (!email || !password) {

          throw new ApiError(HttpStatus.BAD_REQUEST, "Email and password are required");
        }

        // Find user by email
        const user = await User.findOne({ email });

        // Check if user exists
        if (!user) {

			throw new ApiError(HttpStatus.NOT_FOUND, "Invalid Email or Password");
        }

        // Check if user verified
        if (!user.is_verified) {
			
			throw new ApiError(HttpStatus.UNAUTHORIZED, "Your account is not verified");
        }

        // Compare passwords / Check Password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          
			throw new ApiError(HttpStatus.UNAUTHORIZED, "Invalid email or password");
        }

        // Generate tokens
        const { accessToken, refreshToken, accessTokenExp, refreshTokenExp } = await generateTokens(user)

        // Set Cookies
        setTokensCookies(res, accessToken, refreshToken, accessTokenExp, refreshTokenExp)

        // Send success response with tokens
        const apiResponse = new ApiResponse(HttpStatus.OK, {

			user: { id: user._id, email: user.email, name: user.name, roles: user.roles[0] },
			access_token: accessToken,
			refresh_token: refreshToken,
			access_token_exp: accessTokenExp,
			is_auth: true
		}, "Login successful");

		res.status(HttpStatus.OK).json(apiResponse);

      	} catch (error) {
			if (error instanceof ApiError) {
				res.status(error.statusCode).json({
				status: "failed",
				message: error.message,
				errors: error.errors
				});
			} else {
				console.error(error);
				res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
				status: "failed",
				message: "Unable to login, please try again later"
				});
			}
      	}

})

// Get New Access Token OR Refresh Token
const getNewAccessToken = asyncHandler(async (req, res, next) => {

	// TODO:
    // get new access token using Refresh Token
    // set new Tokens to Cookie
	// send success response with new tokens

    try {
        // Get new access token using Refresh Token
        const { newAccessToken, newRefreshToken, newAccessTokenExp, newRefreshTokenExp } = await refreshAccessToken(req, res)

        // Set New Tokens to Cookie
    	setTokensCookies(res, newAccessToken, newRefreshToken, newAccessTokenExp, newRefreshTokenExp);

        // Send success response with new tokens
    	const apiResponse = new ApiResponse(HttpStatus.OK, {
			access_token: newAccessToken,
			refresh_token: newRefreshToken,
			access_token_exp: newAccessTokenExp
		}, "New tokens generated");

		res.status(HttpStatus.OK).json(apiResponse);

    } catch (error) {
        if (error instanceof ApiError) {
			res.status(error.statusCode).json({
			  status: "failed",
			  message: error.message,
			  errors: error.errors
			});
		} else {
			console.error(error);
			res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
			  status: "failed",
			  message: "Unable to generate new token, please try again later"
			});
		}
    }

})

// Profile OR Logged in User
const userProfile = asyncHandler ( async (req,res) =>{

	// TODO:
    // get the user from the request
    // check if user exists in the request
	// send success response with user profile data

	try {
		
		// Get the user from the request
		const user = req.user;

		// Check if user exists in the request
		if (!user) {
			throw new ApiError(HttpStatus.UNAUTHORIZED, "User not authenticated");
		}
	
		// Send success response with user profile data
		const apiResponse = new ApiResponse(HttpStatus.OK, {
			id: user._id,
			name: user.name,
			email: user.email,
			roles: user.roles,
			is_verified: user.is_verified
		}, "User profile retrieved successfully");
	
		res.status(HttpStatus.OK).json(apiResponse);

	} catch (error) {
		
		if (error instanceof ApiError) {
			res.status(error.statusCode).json({
			  status: "failed",
			  message: error.message,
			  errors: error.errors
			});
		} else {
			console.error(error);
			res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
			  status: "failed",
			  message: "Unable to retrieve user profile, please try again later"
			});
		}
	}

})

// Change Password
const changeUserPassword = asyncHandler ( async (req,res) =>{

	// TODO:
    // get password,password_confirmation from request body
    // check if both password and password_confirmation are provided
	// check if password and password_confirmation match
	// generate salt and hash new password
	// update user's password
	// send success response

	try {
		const { password, password_confirmation } = req.body;
  
		// Check if both password and password_confirmation are provided
		if (!password || !password_confirmation) {
		  
			throw new ApiError(HttpStatus.BAD_REQUEST, "New Password and Confirm New Password are required");
		}
  
		// Check if password and password_confirmation match
		if (password !== password_confirmation) {
		  
			throw new ApiError(HttpStatus.BAD_REQUEST, "New Password and Confirm New Password don't match");
		}
  
		// Generate salt and hash new password
		const salt = await bcrypt.genSalt(Number(process.env.SALT));
    	const newHashPassword = await bcrypt.hash(password, salt);
  
		// Update user's password
		await User.findByIdAndUpdate(req.user._id, { $set: { password: newHashPassword } });
  
		// Send success response
		const apiResponse = new ApiResponse(HttpStatus.OK, null, "Password changed successfully");
    	res.status(HttpStatus.OK).json(apiResponse);
	} catch (error) {
		if (error instanceof ApiError) {
			res.status(error.statusCode).json({
			  status: "failed",
			  message: error.message,
			  errors: error.errors
			});
		} else {
			console.error(error);
			res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
			  status: "failed",
			  message: "Unable to change password, please try again later"
			});
		}
	}
})	

// Send Password Reset Link via Email
const sendUserPasswordResetEmail = asyncHandler ( async (req,res) =>{

	// TODO:
    // get email from request body
    // check if email is provided
	// find user by email
	// generate token for password reset
	// reset Link
	// send password reset email
	// send success response

	try {

		const { email } = req.body;

		// Check if email is provided
		if (!email) {
			
			throw new ApiError(HttpStatus.BAD_REQUEST, "Email field is required");
		}
		// Find user by email
		const user = await User.findOne({ email });

		if (!user) {

			throw new ApiError(HttpStatus.NOT_FOUND, "Email doesn't exist");
		}
		// Generate token for password reset
		const secret = user._id + process.env.JWT_ACCESS_TOKEN_SECRET_KEY;
    	const token = jwt.sign({ userID: user._id }, secret, { expiresIn: '15m' });

		// Reset Link
		const resetLink = `${process.env.FRONTEND_HOST}/account/reset-password-confirm/${user._id}/${token}`;
    	console.log(resetLink);

		// Send password reset email  
		await transporter.sendMail({
			from: process.env.EMAIL_FROM,
			to: user.email,
			subject: "Password Reset Link",
			html: `<p>Hello ${user.name},</p><p>Please <a href="${resetLink}">click here</a> to reset your password.</p>`
		});

		// Send success response
		const apiResponse = new ApiResponse(HttpStatus.OK, null, "Password reset email sent. Please check your email.");
    	res.status(HttpStatus.OK).json(apiResponse);

	} catch (error) {
		if (error instanceof ApiError) {
		res.status(error.statusCode).json({
			status: "failed",
			message: error.message,
			errors: error.errors
		});
		} else {
		console.error(error);
		res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
			status: "failed",
			message: "Unable to send password reset email. Please try again later."
		});
		}
	}
})	

// Password Reset
const userPasswordReset = asyncHandler ( async (req,res) =>{

	// TODO:
    // get password,password_confirmation from request body
	// get id,token from request params
    // check if password and password_confirmation are provided
	// check if password and password_confirmation match
	// find user by ID
	// validate token
	// generate salt and hash new password
	// update user's password
	// send success response

	try {
		const { password, password_confirmation } = req.body;

		const { id, token } = req.params;

		// Check if password and password_confirmation are provided
		if (!password || !password_confirmation) {
			
			throw new ApiError(HttpStatus.BAD_REQUEST, "New Password and Confirm New Password are required");
		}

		// Check if password and password_confirmation match
		if (password !== password_confirmation) {
			
			throw new ApiError(HttpStatus.BAD_REQUEST, "New Password and Confirm New Password don't match");
		}

		// Find user by ID
		const user = await User.findById(id);

		if (!user) {

		  throw new ApiError(HttpStatus.NOT_FOUND, "User not found");
		}
		// Validate token

		const new_secret = user._id + process.env.JWT_ACCESS_TOKEN_SECRET_KEY;

		try {
		  jwt.verify(token, new_secret);
		} catch (error) {

		  if (error.name === "TokenExpiredError")
			{
				throw new ApiError(HttpStatus.BAD_REQUEST, "Token expired. Please request a new password reset link.");
		  	}
		  throw new ApiError(HttpStatus.BAD_REQUEST, "Invalid token");
		}

		// Generate salt and hash new password

		const salt = await bcrypt.genSalt(10);
		const newHashPassword = await bcrypt.hash(password, salt);

  
		// Update user's password
		await User.findByIdAndUpdate(user._id, { $set: { password: newHashPassword } });
  
		// Send success response
		const apiResponse = new ApiResponse(HttpStatus.OK, null, "Password reset successfully");
		res.status(HttpStatus.OK).json(apiResponse);
  
	} catch (error) {
		if (error instanceof ApiError) {
			res.status(error.statusCode).json({
			  status: "failed",
			  message: error.message,
			  errors: error.errors
			});
		} else {
			console.error(error);
			res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
			  status: "failed",
			  message: "Unable to reset password. Please try again later."
			});
		}
	}
})	

// Logout
const userLogout = asyncHandler ( async (req,res) =>{

	
	// TODO:
    // get refreshToken from cookies
	// optionally, you can blacklist the refresh token in the database
	// check if refresh token is provided
	// optionally, you can blacklist the refresh token in the database
	// clear access token and refresh token cookies
	// send success response

	try {

		// Optionally, you can blacklist the refresh token in the database
		const refreshToken = req.cookies.refreshToken;

		// Check if refresh token is provided
		if (!refreshToken) {

			throw new ApiError(HttpStatus.BAD_REQUEST, "Refresh token is required");
		}

		// Optionally, you can blacklist the refresh token in the database
		await UserRefreshTokenModel.findOneAndUpdate(
			{ token: refreshToken },
			{ $set: { blacklisted: true } }
		);
  
		// Clear access token and refresh token cookies
		res.clearCookie('accessToken');
		res.clearCookie('refreshToken');
		res.clearCookie('is_auth');
  
		// Send success response
		const apiResponse = new ApiResponse(HttpStatus.OK, null, "Logout successful");
		res.status(HttpStatus.OK).json(apiResponse);

	} catch (error) {
		if (error instanceof ApiError) {
			res.status(error.statusCode).json({
			  status: "failed",
			  message: error.message,
			  errors: error.errors
			});
		} else {
			console.error(error);
			res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
			  status: "failed",
			  message: "Unable to logout, please try again later"
			});
		}
	}

})


export {
    registerUser,
    verifyEmail,
    loginUser,
    getNewAccessToken,
	userProfile,
	changeUserPassword,
	sendUserPasswordResetEmail,
	userPasswordReset,
	userLogout
}