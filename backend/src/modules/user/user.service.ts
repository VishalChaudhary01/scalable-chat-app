import { User } from '@prisma/client';
import { prisma } from '../../config/db.config';
import { AppError } from '../../utils/app-error';
import { HttpStatus } from '../../config/http.config';

export interface TrimedUser {
  id: string;
  name: string | null;
  email: string;
}

export class UserService {
  static getTrimedUser(user: User): TrimedUser {
    return { id: user.id, name: user.name, email: user.email };
  }

  static async getUserById(id?: string) {
    const user = await prisma.user.findFirst({
      where: { id, emailVerified: true },
    });
    if (!user) {
      throw new AppError('User not found', HttpStatus.NOT_FOUND);
    }

    return { user: this.getTrimedUser(user) };
  }
}
