import mongoose, { Schema } from "mongoose";
import bcrypt from "bcrypt";

// Define the schema for the user
const userSchema = new Schema(
    {
        // Username field
        username: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
            index: true
        },
        // Email field
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true
        },
        // Full name field
        fullName: {
            type: String,
            required: true,
            trim: true,
            index: true
        },
        // Password field (hashed)
        password: {
            type: String,
            required: [true, 'Password is required']
        },
        // Refresh token field
        refreshToken: {
            type: String
        }
    },
    // Additional options
    {
        timestamps: true // Adds createdAt and updatedAt fields
    }
);

// Middleware function to hash the password before saving
userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();

    this.password = await bcrypt.hash(this.password, 10);
    next();
});

// Create and export the User model
export const User = mongoose.model("User", userSchema);
