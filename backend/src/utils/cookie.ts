import { CookieOptions, Request, Response } from 'express';
import { Env } from '../config/env.config';

export const CookieNames = {
  ACCESS_TOKEN: 'chat-app-access-token',
  REFRESH_TOKEN: 'chat-app-refresh-token',
  VERIFICATION_TOKEN: 'chat-app-email-verification-token',
} as const;

export type CookieName = (typeof CookieNames)[keyof typeof CookieNames];

const defaultOptions: CookieOptions = {
  httpOnly: true,
  secure: Env.NODE_ENV === 'production',
  sameSite: Env.NODE_ENV === 'production' ? 'none' : 'lax',
};

export function setCookies(
  res: Response,
  tokens: { name: CookieName; value: string; path?: string; expires?: Date }[]
) {
  tokens.forEach((token) =>
    res.cookie(token.name, token.value, {
      ...defaultOptions,
      path: token.path ? token.path : '/',
      expires: token.expires
        ? token.expires
        : new Date(Date.now() + 15 * 60 * 1000),
    })
  );
}

export function getCookies(req: Request, names: CookieName[]) {
  return names.map((name) => req.cookies[name] ?? null);
}

export function clearCookies(res: Response, names: CookieName[]) {
  names.forEach((name) => res.clearCookie(name));
}
