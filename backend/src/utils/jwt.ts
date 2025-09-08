import jwt from 'jsonwebtoken';
import { Env } from '../config/env.config';
import { VerificationType } from '@prisma/client';

type Unit = 'm' | 'h' | 'd';
export type StringValue = `${number}${Unit}`;

export interface TokenPayload {
  userId?: string;
  sessionId?: string;
  emailVerificationType?: VerificationType;
}

export function signJWT(
  payload: TokenPayload,
  secret: string,
  expiresIn: StringValue = Env.JWT_EXPIRESIN as StringValue
) {
  return jwt.sign(payload, secret, { expiresIn });
}

export function verifyJWT<TPayload>(token: string, secret: string) {
  try {
    const payload = jwt.verify(token, secret) as TPayload;
    return payload;
  } catch {
    return null;
  }
}
