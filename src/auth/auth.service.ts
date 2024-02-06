import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { SignInDto } from './dto';
import { JwtPayload, Tokens } from './types';
import { OAuth2Client } from 'google-auth-library';

const AT_EXPIRY = 2 * 60;
const RT_EXPIRY = 5 * 60;

function generateTimestampWithDelay(delayInSeconds) {
  return Date.now() + delayInSeconds * 1000;
}

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private config: ConfigService,
  ) {}

  async signinOauth(dto: SignInDto): Promise<Tokens> {
    const client = new OAuth2Client();
    const payload = await client
      .verifyIdToken({
        idToken: dto.token,
        audience: this.config.get('GOOGLE_CLIENT_ID'),
      })
      .then((token) => token.getPayload());
    // console.log('token payload:::', payload);
    const tokens = await this.getTokens({
      sub: +payload.sub,
      email: payload.email,
      role: 'Admin', //get role from db, create user if needed
    });
    return Object.assign(tokens, {
      access_token_expiry: generateTimestampWithDelay(AT_EXPIRY),
      refresh_token_expiry: generateTimestampWithDelay(RT_EXPIRY),
    });
  }

  async refreshTokens(user: JwtPayload): Promise<Tokens> {
    // console.log({ refreshTokensUser: user });
    const tokens = await this.getTokens({
      sub: +user.sub,
      email: user.email,
      role: user.role,
    });

    return Object.assign(tokens, {
      access_token_expiry: generateTimestampWithDelay(AT_EXPIRY),
      refresh_token_expiry: generateTimestampWithDelay(RT_EXPIRY),
    });
  }

  async getTokens(payload: JwtPayload & { role: string }): Promise<Tokens> {
    const [access_token, refresh_token] = [
      this.jwtService.sign(payload, {
        secret: this.config.get<string>('AT_SECRET'),
        expiresIn: AT_EXPIRY,
      }),
      this.jwtService.sign(payload, {
        secret: this.config.get<string>('RT_SECRET'),
        expiresIn: RT_EXPIRY,
      }),
    ];

    return {
      access_token,
      refresh_token,
    };
  }
}
