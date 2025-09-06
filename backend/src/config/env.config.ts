import { getEnv } from '../utils/get-env';

export const Env = {
  PORT: getEnv('PORT'),
} as const;
