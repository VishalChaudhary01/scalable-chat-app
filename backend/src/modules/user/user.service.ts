import { User } from '@prisma/client';

export class UserService {
  static getTrimedUser(user: User) {
    return { id: user.id, name: user.name, email: user.email };
  }
}
