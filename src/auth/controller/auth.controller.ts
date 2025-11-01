import { Body, Controller, Get, HttpCode, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from '../service/auth.service';
import { RegisterDto } from '../dto/register.dto';
import { LoginDto } from '../dto/login.dto';
import { JwtAuthGuard } from '../jwt/guards/jwtAuth.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @HttpCode(200)
  async register(@Body() body: RegisterDto) {
    return await this.authService.register(
      body.email,
      body.password,
      body.name,
    );
  }

  @Post('login')
  @HttpCode(200)
  async login(@Body() body: LoginDto) {
    return await this.authService.login({
      email: body.email,
      password: body.password,
    });
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(200)
  async logout(@Req() req) {
    const userId = req.user.sub;
    return await this.authService.logout(userId);
  }

  @UseGuards(JwtAuthGuard)
  @Get('user/profile')
  @HttpCode(200)
  async getUserProfile(@Req() req) {
    console.log(req);
    const userId = req.user.sub;
    return await this.authService.getUserProfile(userId);
  }
}
