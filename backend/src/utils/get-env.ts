export function getEnv(key: string, defaultValue = '') {
  const value = process.env[key];

  if (!value) {
    if (!defaultValue) {
      throw new Error(`Environment variable ${key} not set in .env file`);
    }
    return defaultValue;
  }
  return value;
}
