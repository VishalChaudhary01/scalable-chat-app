import { Request } from 'express';
import { VerificationType } from '@prisma/client';
import { prisma } from '../../config/db.config';
import { comparePassword, hashPassword } from '../../utils/bcrypt';
import { generateCode } from '../../utils/crypto';
import {
  ForgotPasswordInput,
  ResetPasswordInput,
  SigninInput,
  SignupInput,
  VerifyEmailInput,
  VerifyResetCodeInput,
} from './auth.validator';
import { calculateDate } from '../../utils/date-time';
import { Env } from '../../config/env.config';
import { signJWT, StringValue, TokenPayload, verifyJWT } from '../../utils/jwt';
import { CookieNames, getCookies } from '../../utils/cookie';
import { AppError } from '../../utils/app-error';
import { HttpStatus } from '../../config/http.config';
import { logger } from '../../utils/logger';
import { UserService } from '../user/user.service';

export class AuthService {
  static async registerUser(data: SignupInput) {
    const hashedPassword = await hashPassword(data.password);
    const code = generateCode();

    const { user, emailVerificationType } = await prisma.$transaction(
      async (tx) => {
        const user = await tx.user.create({
          data: { ...data, password: hashedPassword },
        });

        await tx.verificationToken.deleteMany({
          where: { userId: user.id, type: VerificationType.CONFIRM_EMAIL },
        });

        const emailVerification = await tx.verificationToken.create({
          data: {
            userId: user.id,
            type: VerificationType.CONFIRM_EMAIL,
            token: code,
            expiresAt: calculateDate(Env.JWT_EXPIRESIN as StringValue),
          },
        });

        console.log('Verification token', emailVerification);

        return {
          user: UserService.getTrimedUser(user),
          emailVerificationType: emailVerification.type,
        };
      }
    );

    const verificationToken = signJWT(
      { userId: user.id, emailVerificationType },
      Env.JWT_VERIFICATION_SECRET
    );

    return { user, emailVerificationType, verificationToken };
  }

  static async verifyEmail(
    req: Request,
    data: VerifyEmailInput,
    userAgent?: string
  ) {
    const token = getCookies(req, [CookieNames.VERIFICATION_TOKEN])[0];
    const payload = verifyJWT<TokenPayload>(token, Env.JWT_VERIFICATION_SECRET);
    if (!payload || !payload.userId || !payload.emailVerificationType) {
      throw new AppError(
        'Invalid of expired verification code',
        HttpStatus.BAD_REQUEST
      );
    }
    const { userId, emailVerificationType } = payload;

    const user = await prisma.user.findFirst({
      where: { id: userId },
    });
    if (!user) {
      throw new AppError(
        'Invalid of expired verification code',
        HttpStatus.BAD_REQUEST
      );
    }

    const verificationToken = await prisma.verificationToken.findFirst({
      where: {
        userId,
        type: emailVerificationType,
        token: data.code,
        expiresAt: { gt: new Date(Date.now()) },
      },
    });
    if (!verificationToken) {
      throw new AppError(
        'Invalid of expired verification code',
        HttpStatus.BAD_REQUEST
      );
    }

    await prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: userId },
        data: {
          emailVerified: true,
        },
      });
      await tx.verificationToken.deleteMany({
        where: { userId, type: emailVerificationType },
      });
    });

    const session = await prisma.session.create({
      data: {
        userId: user.id,
        userAgent,
        expiresAt: calculateDate(Env.JWT_REFRESH_EXPIRESIN as StringValue),
      },
    });

    const accessToken = signJWT(
      {
        userId: user.id,
        sessionId: session.id,
      },
      Env.JWT_ACCESS_SECRET
    );

    const refreshToken = signJWT(
      { sessionId: session.id },
      Env.JWT_REFRESH_SECRET,
      Env.JWT_REFRESH_EXPIRESIN as StringValue
    );

    return { user: UserService.getTrimedUser(user), accessToken, refreshToken };
  }

  static async resendCode(req: Request) {
    const token = getCookies(req, [CookieNames.VERIFICATION_TOKEN])[0];
    const payload = verifyJWT<TokenPayload>(token, Env.JWT_VERIFICATION_SECRET);

    if (!payload || !payload.userId || !payload.emailVerificationType) {
      throw new AppError(
        'Invalid of expired verification session',
        HttpStatus.BAD_REQUEST
      );
    }
    const { userId, emailVerificationType } = payload;

    const user = await prisma.user.findFirst({
      where: { id: userId },
    });
    if (!user) {
      throw new AppError(
        'Invalid of expired verification session',
        HttpStatus.BAD_REQUEST
      );
    }

    const verificationDocs = await prisma.verificationToken.findFirst({
      where: {
        userId,
        type: emailVerificationType,
        expiresAt: { gt: new Date(Date.now()) },
      },
    });
    if (!verificationDocs) {
      throw new AppError(
        'Invalid of expired verification session',
        HttpStatus.BAD_REQUEST
      );
    }

    if (verificationDocs.createdAt > new Date(Date.now() - 60 * 1000)) {
      throw new AppError('Too many request', HttpStatus.TOO_MANY_REQUESTS);
    }

    const { verification } = await prisma.$transaction(async (tx) => {
      await tx.verificationToken.deleteMany({
        where: { userId, type: emailVerificationType },
      });

      const verification = await tx.verificationToken.create({
        data: {
          userId,
          type: emailVerificationType,
          token: generateCode(),
          expiresAt: calculateDate(Env.JWT_EXPIRESIN as StringValue),
        },
      });
      return { verification };
    });

    return { user: UserService.getTrimedUser(user), verification };
  }

  static async signinUser(data: SigninInput, userAgent?: string) {
    const user = await prisma.user.findFirst({
      where: { email: data.email, emailVerified: true },
    });
    if (!user) {
      logger.warn(`Login Failed: User with email ${data.email} not found`);
      throw new AppError('Invalid email or password', HttpStatus.BAD_REQUEST);
    }

    if (user.password) {
      await comparePassword(data.password, user.password);
    }

    const session = await prisma.session.create({
      data: {
        userId: user.id,
        userAgent,
        expiresAt: calculateDate(Env.JWT_REFRESH_EXPIRESIN as StringValue),
      },
    });

    const accessToken = signJWT(
      {
        userId: user.id,
        sessionId: session.id,
      },
      Env.JWT_ACCESS_SECRET
    );

    const refreshToken = signJWT(
      { sessionId: session.id },
      Env.JWT_REFRESH_SECRET,
      Env.JWT_REFRESH_EXPIRESIN as StringValue
    );

    return { user: UserService.getTrimedUser(user), accessToken, refreshToken };
  }

  static async forgotPassword(data: ForgotPasswordInput) {
    const user = await prisma.user.findFirst({ where: { email: data.email } });
    if (!user) {
      throw new AppError(
        'No account found with this email address',
        HttpStatus.NOT_FOUND
      );
    }

    const { emailVerificationType } = await prisma.$transaction(async (tx) => {
      await tx.verificationToken.deleteMany({
        where: { userId: user.id, type: VerificationType.PASSWORD_RESET },
      });

      const emailVerification = await tx.verificationToken.create({
        data: {
          userId: user.id,
          type: VerificationType.PASSWORD_RESET,
          token: generateCode(),
          expiresAt: calculateDate(Env.JWT_EXPIRESIN as StringValue),
        },
      });

      return { emailVerificationType: emailVerification.type };
    });

    const verificationToken = signJWT(
      { userId: user.id, emailVerificationType: emailVerificationType },
      Env.JWT_VERIFICATION_SECRET
    );

    return { user, emailVerificationType, verificationToken };
  }

  static async verifyResetCode(req: Request, data: VerifyResetCodeInput) {
    const token = getCookies(req, [CookieNames.VERIFICATION_TOKEN])[0];

    const payload = verifyJWT<TokenPayload>(token, Env.JWT_VERIFICATION_SECRET);

    if (!payload || !payload.userId || !payload.emailVerificationType) {
      throw new AppError(
        'Invalid of expired verification code',
        HttpStatus.BAD_REQUEST
      );
    }
    const { userId, emailVerificationType } = payload;

    const user = await prisma.user.findFirst({
      where: { id: userId },
    });
    if (!user) {
      throw new AppError(
        'Invalid of expired verification code',
        HttpStatus.BAD_REQUEST
      );
    }

    const verificationToken = await prisma.verificationToken.findFirst({
      where: {
        userId,
        type: emailVerificationType,
        token: data.code,
        expiresAt: { gt: new Date(Date.now()) },
      },
    });
    if (!verificationToken) {
      throw new AppError(
        'Invalid of expired verification code',
        HttpStatus.BAD_REQUEST
      );
    }
  }

  static async resetPassword(req: Request, data: ResetPasswordInput) {
    const verificationToken = getCookies(req, [
      CookieNames.VERIFICATION_TOKEN,
    ])[0];

    const payload = verifyJWT<TokenPayload>(
      verificationToken,
      Env.JWT_VERIFICATION_SECRET
    );

    if (!payload || !payload.userId || !payload.emailVerificationType) {
      throw new AppError(
        'Invalid of expired verification code',
        HttpStatus.BAD_REQUEST
      );
    }
    const { userId } = payload;

    const hashedPassword = await hashPassword(data.password);

    await prisma.user.update({
      where: { id: userId },
      data: { password: hashedPassword },
    });

    await prisma.verificationToken.deleteMany({
      where: { userId: payload.userId, type: VerificationType.PASSWORD_RESET },
    });

    await prisma.session.deleteMany({
      where: { userId: userId },
    });
  }
}
