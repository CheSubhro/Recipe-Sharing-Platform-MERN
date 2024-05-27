
import jwt from 'jsonwebtoken';
import  HttpStatus  from '../utils/HttpStatus.js';

const authMiddleware = (req, res, next) => {

    const token = req.headers.authorization;
	console.log(token)
    if (!token) {
      return res.status(HttpStatus.UNAUTHORIZED).json({ message: 'Unauthorized' });
    }
    try {
      const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
	  console.log(decodedToken)
      req.userId = decodedToken.userId;
      next();
    } catch (error) {
      console.error(error);
      res.status(HttpStatus.UNAUTHORIZED).json({ message: 'Unauthorized 4' });
    }
};

export {authMiddleware} ;
