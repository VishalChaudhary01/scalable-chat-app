import { Request, Response } from 'express';
import { HttpStatus } from '../../config/http.config';
import { UserService } from './user.service';

export class UserController {
  static async getProfile(req: Request, res: Response) {
    const userId = req.userId;
    const { user } = await UserService.getUserById(userId);

    res.status(HttpStatus.OK).json({
      message: 'Profile fetch successful',
      user,
    });
  }
}
