import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';

import { Public, GetCurrentUser } from '../common/decorators';
import { RtGuard } from '../common/guards';
import { AuthService } from './auth.service';
import { JwtPayload, Tokens } from './types';
import { SignInDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('signin')
  @HttpCode(HttpStatus.OK)
  signinOauth(@Body() dto: SignInDto): Promise<Tokens> {
    return this.authService.signinOauth(dto);
  }

  @Public()
  @UseGuards(RtGuard)
  @Get('refresh-token')
  @HttpCode(HttpStatus.OK)
  refreshTokens(@GetCurrentUser() user: JwtPayload): Promise<Tokens> {
    return this.authService.refreshTokens(user);
  }

  @Get('profile')
  getProfile() {
    return { username: 'Demo', age: 22 };
  }
}
