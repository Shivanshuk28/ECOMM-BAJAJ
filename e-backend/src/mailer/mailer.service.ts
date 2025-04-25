import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailerService {
  private transporter: nodemailer.Transporter;
  private readonly logger = new Logger(MailerService.name);

  constructor(private configService: ConfigService) {
    // Log mail configuration during initialization
    this.logger.log('Initializing mail service...');
    
    this.transporter = nodemailer.createTransport({
      host: this.configService.get<string>('mail.host', 'smtp.gmail.com'),
      port: this.configService.get<number>('mail.port', 587),
      secure: false, // true for 465, false for other ports
      auth: {
        user: this.configService.get<string>('mail.user', ''),
        pass: this.configService.get<string>('mail.password', ''),
      },
    });
    
    // Test the connection and log the result
    this.transporter.verify()
      .then(() => this.logger.log('Mail service ready'))
      .catch(err => this.logger.error(`Mail configuration error: ${err.message}`));
  }

  async sendOtpEmail(to: string, otp: string): Promise<void> {
    this.logger.log(`Attempting to send OTP email to: ${to}`);
    
    const mailOptions = {
      from: this.configService.get<string>('mail.from', 'noreply@bajajecomm.com'),
      to,
      subject: 'Your OTP Code for Account Verification',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e6e6e6; border-radius: 5px;">
          <h2 style="color: #333;">Email Verification</h2>
          <p>Thank you for signing up. To complete your registration, please use the following OTP code:</p>
          <div style="background-color: #f9f9f9; padding: 15px; border-radius: 5px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
            ${otp}
          </div>
          <p>This code is valid for 5 minutes.</p>
          <p style="color: #777; font-size: 12px; margin-top: 30px;">If you didn't request this email, please ignore it.</p>
        </div>
      `,
    };

    try {
      const info = await this.transporter.sendMail(mailOptions);
      this.logger.log(`Email sent successfully: ${info.messageId}`);
    } catch (error) {
      this.logger.error(`Failed to send email: ${error.message}`);
      throw new Error(`Failed to send OTP email: ${error.message}`);
    }
  }
}