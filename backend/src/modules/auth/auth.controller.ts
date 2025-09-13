import { NextFunction, Request, Response } from 'express';
import { prisma } from '../../config/db.config';
import {
  ForgotPasswordInput,
  ResetPasswordInput,
  SigninInput,
  SignupInput,
  VerifyEmailInput,
  VerifyResetCodeInput,
} from './auth.validator';
import { AppError } from '../../utils/app-error';
import { HttpStatus } from '../../config/http.config';
import { clearCookies, CookieNames, setCookies } from '../../utils/cookie';
import { StringValue } from '../../utils/jwt';
import { Env } from '../../config/env.config';
import { calculateDate } from '../../utils/date-time';
import { AuthService } from './auth.service';
import { logger } from '../../utils/logger';
import passport from 'passport';
import { UserWithJWT } from '../../config/passport.config';

export class AuthController {
  static async signup(req: Request, res: Response) {
    const data: SignupInput = req.body;

    const existingUser = await prisma.user.findFirst({
      where: { email: data.email, emailVerified: true },
    });
    if (existingUser) {
      throw new AppError(
        'User already exist with given email',
        HttpStatus.BAD_REQUEST
      );
    }

    const { user, emailVerificationType, verificationToken } =
      await AuthService.registerUser(data);

    logger.info('User: ', user, emailVerificationType);

    // TODO -> SENT CODE TO EMAIL

    setCookies(res, [
      { name: CookieNames.VERIFICATION_TOKEN, value: verificationToken },
    ]);

    res.status(HttpStatus.CREATED).json({
      message: 'User registered successfully, Please verify you email',
    });
  }

  static async verifyEmail(req: Request, res: Response) {
    const data: VerifyEmailInput = req.body;
    const userAgent = req.headers['user-agent'];

    const { user, accessToken, refreshToken } = await AuthService.verifyEmail(
      req,
      data,
      userAgent
    );

    clearCookies(res, [
      CookieNames.VERIFICATION_TOKEN,
      CookieNames.ACCESS_TOKEN,
      CookieNames.REFRESH_TOKEN,
    ]);

    setCookies(res, [
      { name: CookieNames.ACCESS_TOKEN, value: accessToken },
      {
        name: CookieNames.REFRESH_TOKEN,
        value: refreshToken,
        path: '/auth/refresh-token',
        expires: calculateDate(Env.JWT_REFRESH_EXPIRESIN as StringValue),
      },
    ]);

    res.status(HttpStatus.OK).json({
      message: 'Email verified successfully, User logged in',
      user,
    });
  }

  static async resendCode(req: Request, res: Response) {
    const { user, verification } = await AuthService.resendCode(req);
    console.log(user, verification);

    // TODO -> SENT CODE TO EMAIL

    res.status(HttpStatus.OK).json({
      message: 'Verification Code Resend successful, Please check you email',
    });
  }

  static async signin(req: Request, res: Response) {
    const data: SigninInput = req.body;
    const userAgent = req.headers['user-agent'];

    const { user, accessToken, refreshToken } = await AuthService.signinUser(
      data,
      userAgent
    );

    setCookies(res, [
      { name: CookieNames.ACCESS_TOKEN, value: accessToken },
      {
        name: CookieNames.REFRESH_TOKEN,
        value: refreshToken,
        path: '/auth/refresh-token',
        expires: calculateDate(Env.JWT_REFRESH_EXPIRESIN as StringValue),
      },
    ]);

    res.status(HttpStatus.OK).json({
      message: 'User logged in successfully',
      user,
    });
  }

  static async forgotPassword(req: Request, res: Response) {
    const data: ForgotPasswordInput = req.body;

    const { user, emailVerificationType, verificationToken } =
      await AuthService.forgotPassword(data);

    logger.info('User: ', user, emailVerificationType);

    // TODO -> SENT CODE TO EMAIL

    setCookies(res, [
      { name: CookieNames.VERIFICATION_TOKEN, value: verificationToken },
    ]);

    res.status(HttpStatus.OK).json({ message: 'Enter you verification code' });
  }

  static async verifyResetCode(req: Request, res: Response) {
    const data: VerifyResetCodeInput = req.body;

    await AuthService.verifyResetCode(req, data);

    res
      .status(HttpStatus.OK)
      .json({ message: 'Code verified, proceed to reset password' });
  }

  static async resetPassword(req: Request, res: Response) {
    const data: ResetPasswordInput = req.body;

    await AuthService.resetPassword(req, data);

    clearCookies(res, [
      CookieNames.VERIFICATION_TOKEN,
      CookieNames.ACCESS_TOKEN,
      CookieNames.REFRESH_TOKEN,
    ]);

    res.status(200).json({
      message: 'Password reset successful, Please login with new password',
    });
  }

  static async signout(req: Request, res: Response) {
    const sessionId = req.sessionId;
    await prisma.session.delete({ where: { id: sessionId } });

    clearCookies(res, [
      CookieNames.ACCESS_TOKEN,
      CookieNames.REFRESH_TOKEN,
      CookieNames.VERIFICATION_TOKEN,
    ]);

    res.status(HttpStatus.OK).json({
      message: 'Log-out successful',
    });
  }

  // GOOGLE AUTH
  static googleAuth(req: Request, res: Response, next: NextFunction) {
    passport.authenticate('google', {
      scope: ['profile', 'email'],
      session: false,
    })(req, res, next);
  }

  static async googleAuthCallback(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    try {
      await new Promise<void>((resolve, reject) => {
        passport.authenticate(
          'google',
          { session: false },
          (err: any, user: UserWithJWT | false) => {
            if (err) {
              return reject(
                new AppError('Authentication failed', HttpStatus.UNAUTHORIZED)
              );
            }

            if (!user) {
              return reject(
                new AppError('Authentication failed', HttpStatus.UNAUTHORIZED)
              );
            }

            clearCookies(res, [
              CookieNames.ACCESS_TOKEN,
              CookieNames.REFRESH_TOKEN,
              CookieNames.VERIFICATION_TOKEN,
            ]);

            setCookies(res, [
              { name: CookieNames.ACCESS_TOKEN, value: user.accessToken },
              {
                name: CookieNames.REFRESH_TOKEN,
                value: user.refreshToken,
                path: '/auth/refresh-token',
                expires: calculateDate(
                  Env.JWT_REFRESH_EXPIRESIN as StringValue
                ),
              },
            ]);

            return resolve(res.redirect(`${Env.FRONTEND_URL}`));
          }
        )(req, res, next);
      });
    } catch (error) {
      logger.error('Unexpected Google auth error:', error);
      next(error);
    }
  }
}
