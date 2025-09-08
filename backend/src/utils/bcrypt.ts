import bcrypt from 'bcryptjs';
import { AppError } from './app-error';
import { HttpStatus } from '../config/http.config';

export async function hashPassword(password: string) {
  return await bcrypt.hash(password, 12);
}

export async function comparePassword(password: string, hashed: string) {
  const isValid = await bcrypt.compare(password, hashed);
  if (!isValid) {
    throw new AppError('Invalid email or password', HttpStatus.BAD_REQUEST);
  }
}
