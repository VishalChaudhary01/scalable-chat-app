import { HttpStatus } from '../config/http.config';
import { AppError } from './app-error';

export function getEnv(key: string, defaultValue = '') {
  const value = process.env[key];

  if (!value) {
    if (!defaultValue) {
      throw new AppError(
        `Environment variable ${key} not set in .env file`,
        HttpStatus.NOT_FOUND
      );
    }
    return defaultValue;
  }
  return value;
}
