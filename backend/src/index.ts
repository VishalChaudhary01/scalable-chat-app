import express, { NextFunction, Request, Response } from 'express';
import { Env } from './config/env.config';
import { errorHandler } from './middlewares/error-handler';
import { AppError } from './utils/app-error';
import { HttpStatus } from './config/http.config';

const app = express();

const PORT = Env.PORT;

app.get('/health', (_req: Request, res: Response) => {
  res.status(200).json({ message: 'Healthy server!' });
});

app.use((req: Request, _res: Response, next: NextFunction) => {
  next(new AppError(`API route ${req.path} not found`, HttpStatus.NOT_FOUND));
});

app.use(errorHandler);

app.listen(PORT, () =>
  console.log(`Server running at http://localhost${PORT}`)
);
