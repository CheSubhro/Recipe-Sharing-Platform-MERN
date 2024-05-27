
import { asyncHandler } from '../utils/AsyncHandler.js'
import { ApiError } from '../utils/ApiError.js'
import HttpStatus from '../utils/HttpStatus.js'
import { ApiResponse } from '../utils/ApiResponse.js'
import { lowercase } from '../utils/StringUtils.js'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import { User } from '../models/user.model.js'


const registerUser = asyncHandler ( async (req,res) =>{

    // TODO:
    // get user details from frontend
    // validation - not empty
    // check if user already exists: username, email
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res

    const {fullName, email, username, password } = req.body
    // console.log("email: ", email);

    
    if (
        [fullName, email, username, password].some((field) => field?.trim() === "")
    ) {
        throw new ApiError(HttpStatus.BAD_REQUEST, "All fields are required");
    }

    // Check if the username already exists
    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    })

    if (existedUser) {
        throw new ApiError(HttpStatus.CONFLICT, "User with email or username already exists")
    }

    // Convert username to lowercase
    const lowercaseUsername = lowercase(username);

    const user = await User.create({
        fullName,
        email, 
        password,
        username: lowercaseUsername
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if (!createdUser) {
        throw new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, "Something went wrong while registering the user")
    }

    return res.status(HttpStatus.CREATED).json(
        new ApiResponse(HttpStatus.OK, createdUser, "User registered Successfully")
    )



})

const loginUser = asyncHandler ( async (req,res) =>{

    // TODO:
    // get user details from frontend
    // validation - not empty
    // Check if the password is correct
    // Generate JWT token
    // return res
    try {
        const { username, password } = req.body;

        if ([username, password].some((field) => field?.trim() === "")) {
            throw new ApiError(HttpStatus.BAD_REQUEST, "All fields are required");
        }

        // Find the user by username
        const user = await User.findOne({ username });

        if (!user) {
            throw new ApiError(HttpStatus.BAD_REQUEST, 'Invalid credentials');
        }

        // Check if the password is correct
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            throw new ApiError(HttpStatus.BAD_REQUEST, 'Invalid credentials');
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user._id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: process.env.ACCESS_TOKEN_EXPIRY });

        // Respond with the token
        res.status(HttpStatus.OK).json(new ApiResponse(HttpStatus.OK, { token }, "Login successful"));

    } catch (error) {
        console.error(error);
        if (error instanceof ApiError) {
            res.status(error.statusCode).json(new ApiResponse(error.statusCode, null, error.message));
        } else {
            res.status(HttpStatus.INTERNAL_SERVER_ERROR).json(new ApiResponse(HttpStatus.INTERNAL_SERVER_ERROR, null, 'Internal server error'));
        }
    }

})

export {
    registerUser,
    loginUser
}