
// import { asyncHandler } from '../utils/AsyncHandler.js'
// import { ApiError } from '../utils/ApiError.js'
// import HttpStatus from '../utils/HttpStatus.js'
// import { ApiResponse } from '../utils/ApiResponse.js'
// import { User } from "../models/user.model.js";

// const getUserProfile  = asyncHandler ( async (req,res) =>{

//     // TODO:
//     // get user details from DB
//     // return res

//     try {
//         const user = await User.findById(req.userId);
//         if (!user) {
//             throw new ApiError(HttpStatus.NOT_FOUND, 'User not found');
//         }
//         res.status(HttpStatus.OK).json(new ApiResponse(HttpStatus.OK, { user }, 'User profile retrieved successfully'));
//     } catch (error) {
//         console.error(error);
//         if (error instanceof ApiError) {
//             res.status(error.statusCode).json(new ApiResponse(error.statusCode, null, error.message));
//         } else {
//             res.status(HttpStatus.INTERNAL_SERVER_ERROR).json(new ApiResponse(HttpStatus.INTERNAL_SERVER_ERROR, null, 'Internal server error'));
//         }
//     }

// })

// export {
//     getUserProfile
// }