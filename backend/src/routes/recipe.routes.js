

import { Router } from "express";
import passport from 'passport'
import accessTokenAutoRefresh from "../middlewares/accessTokenAutoRefresh.middleware.js";
import { upload } from "../middlewares/multer.middleware.js";
import { createRecipe,addRating,addComment,searchRecipes } from "../controllers/recipe.controller.js";


const router = Router()

router.route("/create").post(
    accessTokenAutoRefresh, 
    passport.authenticate('jwt', { session: false }), 
    upload.single('image'), 
    createRecipe
);

router.route("/rating").post(
    accessTokenAutoRefresh, 
    passport.authenticate('jwt', { session: false }), 
    addRating
);

router.route("/comment").post(
    accessTokenAutoRefresh, 
    passport.authenticate('jwt', { session: false }), 
    addComment
);

router.route("/search").get( searchRecipes );


export default router
