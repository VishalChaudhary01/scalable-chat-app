import { createLogger, format, transports } from 'winston';
import 'winston-daily-rotate-file';
import { Env } from '../config/env.config';

const customFormat = format.printf(({ level, message, timestamp }) => {
  if (message instanceof Error) {
    return `${timestamp} [${level.toUpperCase()}]: ${message.message}${
      Env.NODE_ENV !== 'production' && message.stack ? `\n${message.stack}` : ''
    }`;
  }
  return `${timestamp} [${level.toUpperCase()}]: ${message}`;
});

export const logger = createLogger({
  level: Env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: format.combine(
    format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    customFormat
  ),
  transports: [
    new transports.Console(),
    new transports.DailyRotateFile({
      dirname: 'logs',
      filename: 'chat-server-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '14d',
    }),
  ],
});
