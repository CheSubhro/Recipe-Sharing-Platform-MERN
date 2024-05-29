
import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import passport from 'passport';
import './config/passport-jwt-strategy.js'


const app = express()

// This will solve CORS Policy Error
const corsOptions = {
    // set origin to a specific origin.
    origin: process.env.FRONTEND_HOST,
    credentials: true,
    optionsSuccessStatus: 200,
};

app.use(cors(corsOptions))

app.use(express.json({limit: "16kb"}))
app.use(express.urlencoded({extended: true, limit: "16kb"}))
app.use(express.static("public"))
app.use(cookieParser())

// Passport Middleware
app.use(passport.initialize());


//routes import
// import userRouter from './routes/user.routes.js'
import authRouter from './routes/auth.routes.js'
import recipeRouter from './routes/recipe.routes.js'

//routes declaration
// app.use("/api/v1/users", userRouter)
app.use("/api/v1/auth", authRouter)
app.use("/api/v1/recipe", recipeRouter)


export { app }