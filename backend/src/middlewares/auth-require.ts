import { Request, Response, NextFunction } from 'express';
import { CookieNames, getCookies } from '../utils/cookie';
import { AppError } from '../utils/app-error';
import { HttpStatus } from '../config/http.config';
import { TokenPayload, verifyJWT } from '../utils/jwt';
import { Env } from '../config/env.config';
import { prisma } from '../config/db.config';

export async function authRequire(
  req: Request,
  _res: Response,
  next: NextFunction
) {
  try {
    const token = getCookies(req, [CookieNames.ACCESS_TOKEN])[0];
    if (!token) {
      throw new AppError('Token not found', HttpStatus.UNAUTHORIZED);
    }

    const payload = verifyJWT<TokenPayload>(token, Env.JWT_ACCESS_SECRET);
    if (!payload || !payload.userId || !payload.sessionId) {
      throw new AppError('Invalid or expired token', HttpStatus.UNAUTHORIZED);
    }

    const { userId, sessionId } = payload;

    const user = await prisma.user.findFirst({
      where: { id: userId, emailVerified: true },
    });
    if (!user) {
      throw new AppError('Invalid or expired token', HttpStatus.UNAUTHORIZED);
    }

    req.userId = userId;
    req.sessionId = sessionId;
    next();
  } catch (error) {
    next(error);
  }
}
