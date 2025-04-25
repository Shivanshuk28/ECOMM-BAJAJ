import { Injectable, ConflictException, UnauthorizedException, NotFoundException, Inject, Logger } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Cache } from 'cache-manager';
import { User, UserDocument } from '../users/schemas/user.schema';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { MailerService } from '../mailer/mailer.service';

// Define interface for signup response to include optional OTP
export interface SignupResponse {
  message: string;
  otp?: string;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private mailerService: MailerService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  // Generate a random 6-digit OTP
  private generateOtp(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  async signup(signupDto: SignupDto): Promise<SignupResponse> {
    const { email, password, name, address } = signupDto;

    // Check if user already exists
    const existingUser = await this.userModel.findOne({ email }).exec();
    if (existingUser) {
      throw new ConflictException('Email already registered');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user with unverified status
    const newUser = new this.userModel({
      name,
      email,
      password: hashedPassword,
      isVerified: false,
      address: address || {},
      cart: [],
    });

    await newUser.save();

    // Generate OTP and store it in Redis
    const otp = this.generateOtp();
    const key = `otp:${email}`;
    
    try {
      await this.cacheManager.set(key, otp, 300); // Store OTP for 5 minutes
      this.logger.log(`OTP stored in Redis for ${email}: ${otp}`);
      
      // Immediately verify if OTP was stored correctly
      const verifyStored = await this.cacheManager.get<string>(key);
      this.logger.log(`Verification of Redis storage for ${email}: ${verifyStored ? 'Success' : 'Failed'}`);
    } catch (error) {
      this.logger.error(`Failed to store OTP in Redis: ${error.message}`);
    }

    // Send OTP email
    await this.mailerService.sendOtpEmail(email, otp);
    
    return { 
      message: 'User registered successfully. Please check your email for OTP verification.',
      // Include OTP in response during development for testing
      otp: process.env.NODE_ENV !== 'production' ? otp : undefined 
    };
  }

  async verifyOtp(verifyOtpDto: VerifyOtpDto): Promise<{ message: string }> {
    const { email, otp } = verifyOtpDto;
    const key = `otp:${email}`;
    
    this.logger.log(`Attempting to verify OTP for ${email}: ${otp}`);
    
    // Get stored OTP from Redis
    let storedOtp: string | undefined = undefined;
    
    try {
      const result = await this.cacheManager.get<string | null>(key);
      storedOtp = result === null ? undefined : result;
      this.logger.log(`Retrieved OTP from Redis for ${email}: ${storedOtp || 'not found'}`);
      
      // For debugging only - this is a fallback mechanism
      if (!storedOtp && process.env.NODE_ENV !== 'production') {
        // In development, store the OTP for testing if it doesn't exist
        await this.cacheManager.set(key, otp, 300);
        storedOtp = otp;
        this.logger.warn(`Development mode: Created OTP on-the-fly for testing`);
      }
    } catch (error) {
      this.logger.error(`Error retrieving OTP from Redis: ${error.message}`);
    }
    
    if (!storedOtp) {
      throw new UnauthorizedException('OTP has expired. Please request a new one.');
    }

    if (storedOtp !== otp) {
      this.logger.warn(`Invalid OTP attempt for ${email}. Expected: ${storedOtp}, Received: ${otp}`);
      throw new UnauthorizedException('Invalid OTP. Please try again.');
    }

    // Find and update user verification status
    const user = await this.userModel.findOne({ email }).exec();
    if (!user) {
      throw new NotFoundException('User not found');
    }

    user.isVerified = true;
    await user.save();

    // Remove OTP from cache
    try {
      await this.cacheManager.del(key);
      this.logger.log(`OTP removed from cache for ${email} after successful verification`);
    } catch (error) {
      this.logger.error(`Error removing OTP from Redis: ${error.message}`);
    }

    return { message: 'Email verified successfully.' };
  }

  async resendOtp(email: string): Promise<{ message: string }> {
    // Check if user exists
    const user = await this.userModel.findOne({ email }).exec();
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // If user is already verified
    if (user.isVerified) {
      throw new ConflictException('Email is already verified');
    }

    // Generate new OTP and store it in Redis
    const otp = this.generateOtp();
    await this.cacheManager.set(`otp:${email}`, otp, 300); // Store OTP for 5 minutes

    // Send OTP email
    await this.mailerService.sendOtpEmail(email, otp);
    
    return { message: 'OTP resent successfully. Please check your email.' };
  }

  async login(loginDto: LoginDto): Promise<{ token: string; user: Partial<User> }> {
    const { email, password } = loginDto;

    // Find user by email
    const user = await this.userModel.findOne({ email }).exec();
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if user is verified
    if (!user.isVerified) {
      throw new UnauthorizedException('Please verify your email before logging in');
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Generate JWT token
    const payload = { sub: user._id, email: user.email };
    const token = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('jwt.secret') || 'fallback-secret-key',
      expiresIn: this.configService.get<string>('jwt.expiresIn'),
    });

    // Return user info (excluding password)
    const userResponse = {
      _id: user._id,
      name: user.name,
      email: user.email,
      isVerified: user.isVerified,
      address: user.address,
      cart: user.cart,
    };

    return { token, user: userResponse };
  }
}