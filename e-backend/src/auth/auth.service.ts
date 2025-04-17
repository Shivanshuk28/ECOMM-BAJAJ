import { Injectable, ConflictException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { User, UserDocument } from '../users/schemas/user.schema';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async signup(signupDto: SignupDto): Promise<{ message: string }> {
    const { email, password, name, address } = signupDto;

    // Check if user already exists
    const existingUser = await this.userModel.findOne({ email }).exec();
    if (existingUser) {
      throw new ConflictException('Email already registered');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user with all provided fields
    const newUser = new this.userModel({
      name,
      email,
      password: hashedPassword,
      address: address || {},
      cart: [],
    });

    await newUser.save();

    // Here you would implement OTP verification with Redis later
    
    return { message: 'User registered successfully' };
  }

  async login(loginDto: LoginDto): Promise<{ token: string; user: Partial<User> }> {
    const { email, password } = loginDto;

    // Find user by email
    const user = await this.userModel.findOne({ email }).exec();
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
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