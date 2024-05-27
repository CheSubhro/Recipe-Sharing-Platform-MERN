import mongoose, { Schema } from "mongoose";

// Define the schema for the user
const userSchema = new Schema(
    {
        // Name field
        name: {
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
        // Password field (hashed)
        password: {
            type: String,
            required: [true, 'Password is required'],
            trim: true
        },

        is_verified: { 
            type: Boolean, 
            default: false 
        },
        roles: { 
            type: [String],
            enum: ["user", "admin"],
             default: ["user"] },
    },
    // Additional options
    {
        timestamps: true // Adds createdAt and updatedAt fields
    }
);


// Create and export the User model
export const User = mongoose.model("User", userSchema);
