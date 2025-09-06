import { getEnv } from '../utils/get-env';

export const Env = {
  NODE_ENV: getEnv('NODE_ENV', 'production'),
  PORT: getEnv('PORT'),
} as const;
