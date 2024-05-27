
import mongoose, { Schema } from "mongoose";

// Define the schema for the Recipe
const recipeSchema = new Schema(
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
        // Avatar field (cloudinary URL)
        avatar: {
            type: String,
            required: true
        },
        // Cover image field (cloudinary URL)
        coverImage: {
            type: String
        },
        // Watch history field (array of Video references)
        watchHistory: [
            {
                type: Schema.Types.ObjectId,
                ref: "Video"
            }
        ],
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


// Create and export the Recipe model
export const Recipe = mongoose.model("Recipe", recipeSchema);
