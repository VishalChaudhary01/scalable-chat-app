import express, { NextFunction, Request, Response } from 'express';
import cookieParser from 'cookie-parser';
import { Env } from './config/env.config';
import { errorHandler } from './middlewares/error-handler';
import { AppError } from './utils/app-error';
import { HttpStatus } from './config/http.config';
import { logger } from './utils/logger';
import authRoutes from './modules/auth/auth.route';
import { connectDabase } from './config/db.config';
import { configurePassportStrategy } from './config/passport.config';
import userRoutes from './modules/user/user.route';

const app = express();
app.use(cookieParser());
app.use(express.json());

configurePassportStrategy();

const PORT = Env.PORT;

app.get('/health', (_req: Request, res: Response) => {
  res.status(200).json({ message: 'Healthy server!' });
});

app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/user', userRoutes);

app.use((req: Request, _res: Response, next: NextFunction) => {
  next(new AppError(`API route ${req.path} not found`, HttpStatus.NOT_FOUND));
});

app.use(errorHandler);

app.listen(PORT, async () => {
  await connectDabase();
  logger.info(`Server running at http://localhost${PORT}`);
});
