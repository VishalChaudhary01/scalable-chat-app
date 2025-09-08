import { Request, Response, NextFunction } from 'express';
import { HttpStatus } from '../config/http.config';
import { Env } from '../config/env.config';
import { AppError } from '../utils/app-error';
import { logger } from '../utils/logger';
import { ZodError } from 'zod';

export function errorHandler(
  error: Error,
  req: Request,
  res: Response,
  _next: NextFunction
) {
  logger.warn(`Error occurred at PATH: ${req.path}`, error);

  if (error instanceof AppError) {
    return res.status(error.statusCode).json({
      message: error.message,
    });
  }

  if (error instanceof ZodError) {
    const message = error.issues.map((issue) => `${issue.message}`).join(', ');

    return res.status(HttpStatus.BAD_REQUEST).json({ message });
  }

  return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
    message:
      'We are sorry for the inconvenience. Something went wrong on the server. Please try again later.',
    error:
      Env.NODE_ENV === 'development'
        ? error.message
        : 'Unexpected error occure',
  });
}
