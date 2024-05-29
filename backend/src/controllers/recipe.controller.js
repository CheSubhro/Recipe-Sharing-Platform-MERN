
import { asyncHandler } from '../utils/AsyncHandler.js'
import { ApiError } from '../utils/ApiError.js'
import HttpStatus from '../utils/HttpStatus.js'
import { ApiResponse } from '../utils/ApiResponse.js'
import { Recipe } from '../models/recipe.model.js'

const createRecipe = asyncHandler ( async (req,res) =>{

    // TODO:
    // check if user is loged in or not
    // get recipe details from frontend
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

const addRating = asyncHandler ( async (req,res) =>{

    // TODO:
    // check if user is loged in or not
    // get recipe id rating comment details from frontend
    // validation - not empty
    // find recipe ID
    // create rating object - create entry in db recipe collection
    // return res

        try {

            // Extract user ID from request 
            const userId = req.user._id;

            if (!userId) 
            {
                throw new ApiError(HttpStatus.UNAUTHORIZED, "User not logged in");
            }

            const { recipeId, rating, comment } = req.body;

            if (!recipeId || !rating) {

                throw new ApiError(HttpStatus.BAD_REQUEST, "Recipe ID and rating are required");
            }

            const recipe = await Recipe.findById(recipeId);

            if (!recipe) {

                throw new ApiError(HttpStatus.NOT_FOUND, "Recipe not found");
            }

            const newRating = {
                user: userId,
                rating,
                comment
            };
        
            recipe.ratings.push(newRating);
            await recipe.save();

            return res.status(HttpStatus.OK).json(
                new ApiResponse(HttpStatus.OK, recipe, "Rating added successfully")
            )
        
        
        } catch (error) {
            
            // Handle errors
            return res.status(error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR).json(
                new ApiResponse(error.statusCode || HttpStatus.INTERNAL_SERVER_ERROR, null, error.message)
            );
        }

})    


export {
    createRecipe,
    addRating
}
