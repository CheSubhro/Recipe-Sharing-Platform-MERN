
import mongoose, { Schema } from "mongoose";

// Define the schema for the Rating 

const ratingSchema = new Schema(
    {
        // User field
        user: { 
            type: mongoose.Schema.Types.ObjectId, 
            ref: 'User', 
            required: true 
        },
        // Rating field
        rating: { 
            type: Number, 
            required: true, 
            min: 1, 
            max: 5 
        },
        // Comment field
        comment: { 
            type: String 
        }
    }, 
    {
        timestamps: true // Adds createdAt and updatedAt fields
    }
);

// Define the schema for the Comment 

const commentSchema = new Schema(
    {
        // User field
        user: {
            type: mongoose.Schema.Types.ObjectId, 
            ref: 'User', 
            required: true 
        },
        // Comment field
        comment: { 
            type: String, 
            required: true 
        }
    }, 
    {
        timestamps: true // Adds createdAt and updatedAt fields
    }
);

// Define the schema for the Recipe

const recipeSchema  = new Schema(
    {
        // Title field
        title: { 
            type: String, 
            required: true 
        },
        // Ingredients field
        ingredients: { 
            type: [String], 
            required: true 
        },
        // Instructions field
        instructions: { 
            type: String, 
            required: true 
        },
        // Image field
        image: { 
            type: String 
        },
        // Ratings field
        ratings: [ratingSchema],
        // Comments field
        comments: [commentSchema],
        //Author Field
        author: { 
            type: mongoose.Schema.Types.ObjectId, 
            ref: 'User', 
            required: true 
        }
    },
    // Additional options
    {
        timestamps: true // Adds createdAt and updatedAt fields
    }
);


// Create and export the Recipe model
export const Recipe = mongoose.model("Recipe", recipeSchema);
