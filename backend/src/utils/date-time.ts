import { add } from 'date-fns';
import { StringValue } from './jwt';
import { AppError } from './app-error';
import { HttpStatus } from '../config/http.config';

export function calculateDate(time: StringValue) {
  const match = time.match(/^(\d+)([mhd])$/);
  if (!match) throw new Error('Invalid format. Use "15m", "1h", or "2d".');

  const [, value, unit] = match;
  const date = new Date();

  // Check the unit and apply accordingly
  switch (unit) {
    case 'm': // minutes
      return add(date, { minutes: parseInt(value) });
    case 'h': // hours
      return add(date, { hours: parseInt(value) });
    case 'd': // days
      return add(date, { days: parseInt(value) });
    default:
      throw new AppError(
        'Invalid unit. Use "m", "h", or "d".',
        HttpStatus.BAD_REQUEST
      );
  }
}
