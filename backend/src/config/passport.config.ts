import { Request } from 'express';
import passport, { Profile } from 'passport';
import { Strategy } from 'passport-google-oauth20';
import { prisma } from './db.config';
import { Env } from './env.config';
import { signJWT, StringValue } from '../utils/jwt';
import { calculateDate } from '../utils/date-time';
import { TrimedUser, UserService } from '../modules/user/user.service';

export interface UserWithJWT extends TrimedUser {
  accessToken: string;
  refreshToken: string;
}

export function configurePassportStrategy() {
  passport.use(
    new Strategy(
      {
        clientID: Env.GOOGLE_CLIENT_ID,
        clientSecret: Env.GOOGLE_CLIENT_SECRET,
        callbackURL: Env.GOOGLE_AUTH_CALLBACK,
        passReqToCallback: true,
      },

      async function (
        req: Request,
        _accessToken: string,
        _refreshToken: string,
        profile: Profile,
        done: Function
      ) {
        try {
          let user = await prisma.user.findFirst({
            where: {
              email: profile.emails?.[0]?.value || '',
            },
          });

          if (!user) {
            user = await prisma.user.create({
              data: {
                name: profile.displayName,
                email: profile.emails?.[0]?.value || '',
                emailVerified: true,
                provider: 'GOOGLE',
                providerId: profile.id,
              },
            });
          } else if (!user.emailVerified) {
            user = await prisma.user.update({
              where: { email: profile.emails?.[0]?.value || '' },
              data: {
                provider: 'GOOGLE',
                providerId: profile.id,
                emailVerified: true,
              },
            });
          }

          const userAgent = req.headers['user-agent'] || '';
          const session = await prisma.session.create({
            data: {
              userId: user.id,
              userAgent,
              expiresAt: calculateDate(
                Env.JWT_REFRESH_EXPIRESIN as StringValue
              ),
            },
          });

          const jwtAccessToken = signJWT(
            { userId: user.id, sessionId: session.id },
            Env.JWT_ACCESS_SECRET,
            Env.JWT_EXPIRESIN as StringValue
          );

          const jwtRefreshToken = signJWT(
            { sessionId: session.id },
            Env.JWT_REFRESH_SECRET,
            Env.JWT_REFRESH_EXPIRESIN as StringValue
          );

          const trimedUser: TrimedUser = UserService.getTrimedUser(user);

          const userWithJWT: UserWithJWT = {
            ...trimedUser,
            accessToken: jwtAccessToken,
            refreshToken: jwtRefreshToken,
          };
          return done(null, userWithJWT);
        } catch (error) {
          return done(error, null);
        }
      }
    )
  );
}
