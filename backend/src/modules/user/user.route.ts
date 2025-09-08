import { Router } from 'express';
import { UserController } from './user.controller';
import { authRequire } from '../../middlewares/auth-require';

const userRoutes = Router();

userRoutes.get('/profile', authRequire, UserController.getProfile);

export default userRoutes;
