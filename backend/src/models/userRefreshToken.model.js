
import mongoose, { Schema } from "mongoose";

// Define the schema for the user refresh Token
const userRefreshTokenSchema = new Schema(
    {
        // User ID field
        userId: { 
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User', 
            required: true 
        },
        token: { 
            type: String, 
            required: true 
        },
        blacklisted: {
            type: Boolean, 
            default: false 
        },
        createdAt: { 
            type: Date, 
            default: Date.now, 
            expires: '5d' 
        }
        
    }
);


// Create and export the User model
export const UserRefreshTokenModel = mongoose.model("UserRefreshToken", userRefreshTokenSchema);
