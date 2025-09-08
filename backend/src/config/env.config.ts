import { getEnv } from '../utils/get-env';

export const Env = {
  NODE_ENV: getEnv('NODE_ENV', 'production'),
  PORT: getEnv('PORT'),
  JWT_VERIFICATION_SECRET: getEnv('JWT_VERIFICATION_SECRET'),
  JWT_ACCESS_SECRET: getEnv('JWT_ACCESS_SECRET'),
  JWT_REFRESH_SECRET: getEnv('JWT_REFRESH_SECRET'),
  JWT_EXPIRESIN: getEnv('JWT_EXPIRESIN'),
  JWT_REFRESH_EXPIRESIN: getEnv('JWT_REFRESH_EXPIRESIN'),
  FRONTEND_URL: getEnv('FRONTEND_URL'),
} as const;
