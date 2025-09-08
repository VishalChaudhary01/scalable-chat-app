import z from 'zod';
import {
  codeSchema,
  emailSchema,
  nameSchema,
  passwordSchema,
} from '../../utils/validators';

export const signupSchema = z.object({
  name: nameSchema,
  email: emailSchema,
  password: passwordSchema,
});

export const signinSchema = z.object({
  email: emailSchema,
  password: z.string('Password is required').min(1, 'Password is required'),
});

export const verifyEmailSchema = z.object({
  code: codeSchema,
});

export const forgotPasswordSchema = z.object({
  email: emailSchema,
});

export const verifyResetCodeSchema = z.object({
  code: codeSchema,
});

export const resetPasswordSchema = z.object({
  password: passwordSchema,
});

export type SignupInput = z.infer<typeof signupSchema>;
export type SigninInput = z.infer<typeof signinSchema>;
export type VerifyEmailInput = z.infer<typeof verifyEmailSchema>;
export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>;
export type VerifyResetCodeInput = z.infer<typeof verifyResetCodeSchema>;
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;
