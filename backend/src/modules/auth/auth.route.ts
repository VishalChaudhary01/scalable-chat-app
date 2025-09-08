import { Router } from 'express';
import { AuthController } from './auth.controller';
import { validateInput } from '../../middlewares/validate-input';
import {
  forgotPasswordSchema,
  resetPasswordSchema,
  signinSchema,
  signupSchema,
  verifyEmailSchema,
  verifyResetCodeSchema,
} from './auth.validator';
import { authRequire } from '../../middlewares/auth-require';

const authRoutes = Router();

authRoutes.post('/signup', validateInput(signupSchema), AuthController.signup);
authRoutes.post('/signin', validateInput(signinSchema), AuthController.signin);
authRoutes.post('/resend-code', AuthController.resendCode);
authRoutes.post(
  '/verify-email',
  validateInput(verifyEmailSchema),
  AuthController.verifyEmail
);
authRoutes.post(
  '/forgot-password',
  validateInput(forgotPasswordSchema),
  AuthController.forgotPassword
);
authRoutes.post(
  '/verify-reset-code',
  validateInput(verifyResetCodeSchema),
  AuthController.verifyResetCode
);
authRoutes.post(
  '/reset-password',
  validateInput(resetPasswordSchema),
  AuthController.resetPassword
);

authRoutes.post('/signout', authRequire, AuthController.signout);

export default authRoutes;
