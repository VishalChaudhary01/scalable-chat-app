import { PrismaClient } from '@prisma/client';
import { logger } from '../utils/logger';
import { AppError } from '../utils/app-error';

export const prisma = new PrismaClient();

export async function connectDabase() {
  try {
    await prisma.$connect();
    logger.info('Database connected!');
  } catch (err) {
    logger.error('Database not reachable:', err);
    throw new AppError('Database connrection failed');
  }
}
