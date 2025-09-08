import { Request, Response, NextFunction } from 'express';
import { ZodObject } from 'zod';

export function validateInput(schema: ZodObject) {
  return (req: Request, _res: Response, next: NextFunction) => {
    try {
      schema.parse(req.body);
      next();
    } catch (error) {
      next(error);
    }
  };
}
