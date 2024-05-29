

import { Router } from "express";
import passport from 'passport'
import accessTokenAutoRefresh from "../middlewares/accessTokenAutoRefresh.middleware.js";
import { upload } from "../middlewares/multer.middleware.js";
import { createRecipe } from "../controllers/recipe.controller.js";


const router = Router()

router.route("/create").post(
    accessTokenAutoRefresh, 
    passport.authenticate('jwt', { session: false }), 
    upload.single('image'), 
    createRecipe
);

export default router
