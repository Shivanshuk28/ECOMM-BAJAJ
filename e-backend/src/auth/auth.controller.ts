import { Controller, Post, Body, ValidationPipe, Param, HttpCode } from '@nestjs/common';
import { AuthService, SignupResponse } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signup(@Body(ValidationPipe) signupDto: SignupDto): Promise<SignupResponse> {
    return this.authService.signup(signupDto);
  }

  @Post('verify-otp')
  @HttpCode(200)
  async verifyOtp(@Body(ValidationPipe) verifyOtpDto: VerifyOtpDto) {
    return this.authService.verifyOtp(verifyOtpDto);
  }

  @Post('resend-otp/:email')
  @HttpCode(200)
  async resendOtp(@Param('email') email: string) {
    return this.authService.resendOtp(email);
  }

  @Post('login')
  @HttpCode(200)
  async login(@Body(ValidationPipe) loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }
}