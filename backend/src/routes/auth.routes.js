

import { Router } from "express";
import { registerUser,verifyEmail,loginUser,getNewAccessToken } from "../controllers/auth.controller.js";


const router = Router()

router.route("/register").post(registerUser)
router.route("/verify-email").post(verifyEmail)
router.route("/login").post(loginUser)
router.route("/refresh-token").post(getNewAccessToken)

export default router
