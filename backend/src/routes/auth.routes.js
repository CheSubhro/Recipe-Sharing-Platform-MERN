

import { Router } from "express";
import passport from 'passport'
import setAuthHeader from '../middlewares/setAuthHeader.midlleware.js'
import accessTokenAutoRefresh from '../middlewares/accessTokenAutoRefresh.middleware.js'

import { registerUser,verifyEmail,loginUser,getNewAccessToken,userProfile,changeUserPassword,sendUserPasswordResetEmail,userPasswordReset,userLogout } from "../controllers/auth.controller.js";


const router = Router()

router.route("/register").post(registerUser)
router.route("/verify-email").post(verifyEmail)
router.route("/login").post(loginUser)
router.route("/refresh-token").post(getNewAccessToken)
router.route("/reset-password-link").post(sendUserPasswordResetEmail)
router.route("/reset-password/:id/:token").post(userPasswordReset)

// Protected Routes
router.route('/profile').get(accessTokenAutoRefresh, passport.authenticate('jwt', { session: false }), userProfile);
router.route('/change-password').post(accessTokenAutoRefresh, passport.authenticate('jwt', { session: false }), changeUserPassword);
router.route('/logout').post(accessTokenAutoRefresh, passport.authenticate('jwt', { session: false }), userLogout);



export default router
