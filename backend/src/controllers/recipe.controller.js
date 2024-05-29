
import { asyncHandler } from '../utils/AsyncHandler.js'
import { ApiError } from '../utils/ApiError.js'
import HttpStatus from '../utils/HttpStatus.js'
import { ApiResponse } from '../utils/ApiResponse.js'
import { Recipe } from '../models/recipe.model.js'

const createRecipe = asyncHandler ( async (req,res) =>{

    // TODO:
    // check if user is loged in or not
    // get user details from frontend
    // validation - not empty
    // check for image
    // create recipe object - create entry in db
    // check for recipe creation
    // return res

    // Extract user ID from request (assuming user is added to req in auth middleware)
    const userId = req.user._id;

    if (!userId) 
    {
        throw new ApiError(HttpStatus.UNAUTHORIZED, "User not logged in");
    }

    const { title, ingredients, instructions } = req.body;
    //console.log("title: ", title);

    // Validate fields
    if ([title, ingredients, instructions].some((field) => !field || field.trim() === "")) 
    {
        throw new ApiError(HttpStatus.BAD_REQUEST, "All fields are required");
    }

    const imageLocalPath = req.file?.path;

    if (!imageLocalPath) {
        throw new ApiError(HttpStatus.BAD_REQUEST, "Image file is required");
    }

    const newRecipe = await Recipe.create({
        title,
        ingredients,
        instructions,
        image: imageLocalPath,
        author: userId
    });


    if (!newRecipe) {
        throw new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, "Something went wrong while creating the new recipe");
    }

    return res.status(HttpStatus.CREATED).json(
        new ApiResponse(HttpStatus.CREATED, newRecipe, "New Recipe Created Successfully")
    );


})

export {
    createRecipe
}
