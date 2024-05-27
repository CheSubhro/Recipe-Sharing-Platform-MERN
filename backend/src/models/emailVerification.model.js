

import mongoose, { Schema } from "mongoose";

// Define the schema for the Email Verification
const emailVerificationSchema = new Schema(
    {
        userId: { 
            type: mongoose.Schema.Types.ObjectId, 
            ref: 'User', 
            required: true 
        },
        otp: { 
            type: String, 
            required: true 
        },
        createdAt: { 
            type: Date, 
            default: Date.now, 
            expires: '15m' 
        }
        
    }
);


// Create and export the User model
export const EmailVerificationModel  = mongoose.model("EmailVerification", emailVerificationSchema );
