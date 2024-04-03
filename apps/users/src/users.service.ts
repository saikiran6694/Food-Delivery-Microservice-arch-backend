import { BadRequestException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService, JwtVerifyOptions } from '@nestjs/jwt';
import { ActivationUserDto, LoginDto, RegisterDto } from './dto/user.dto';
import { PrismaService } from '../../../prisma/prisma.service';
import { Response } from 'express';
import * as bcrypt from 'bcrypt';
import { EmailService } from './email/email.service';
import { TokenSender } from './utils/sendToken';

interface UserData {
  name: string;
  email: string;
  password: string;
  phone_number: number;
}

@Injectable()
export class UsersService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prismaService: PrismaService,
    private readonly configService: ConfigService,
    private readonly emailService: EmailService,
  ) {}

  // register user
  async register(registerDto: RegisterDto, response: Response) {
    const { name, email, password, phone_number } = registerDto;

    const userExists = await this.prismaService.user.findUnique({
      where: {
        email,
      },
    });

    if (userExists) {
      throw new BadRequestException({
        message: 'User already registered with this email!',
      });
    }

    const phoneNumberExists = await this.prismaService.user.findUnique({
      where: {
        phone_number,
      },
    });

    if (phoneNumberExists)
      throw new BadRequestException({
        message: 'User already registered with this phone number',
      });

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = { name, email, password: hashedPassword, phone_number };

    const { token: activation_token, activateCode: activationCode } =
      await this.createActivationToken(user);

    await this.emailService.sendMail({
      email,
      subject: 'Activate your account',
      template: './activation-code',
      name,
      activationCode,
    });

    return { activation_token, response };
  }

  // create activation token
  async createActivationToken(user: UserData) {
    const activateCode = Math.floor(1000 + Math.random() * 9000);

    const token = this.jwtService.sign(
      {
        user,
        activateCode,
      },
      {
        secret: this.configService.get<string>('ACTIVATION_SECRET'),
        expiresIn: '5m',
      },
    );

    return { token, activateCode };
  }

  // activation user
  async activateUser(activationDto: ActivationUserDto, response: Response) {
    const { activationToken, activationCode } = activationDto;

    const newUser: { user: UserData; activateCode: string } =
      this.jwtService.verify(activationToken, {
        secret: this.configService.get<string>('ACTIVATION_SECRET'),
      } as JwtVerifyOptions) as { user: UserData; activateCode: string };

    if (newUser.activateCode != activationCode) {
      throw new BadRequestException('Invalid activation code');
    }

    const { name, email, password, phone_number } = newUser.user;

    const existUser = await this.prismaService.user.findUnique({
      where: {
        email,
      },
    });

    if (existUser) {
      throw new BadRequestException('User already exist with this email!');
    }

    const user = await this.prismaService.user.create({
      data: {
        name,
        email,
        password,
        phone_number,
      },
    });

    return { user, response };
  }

  // login user
  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;
    const user = await this.prismaService.user.findUnique({
      where: {
        email,
      },
    });

    if (user && this.comparePassword(password, user.password)) {
      const tokenSender = new TokenSender(this.configService, this.jwtService);
      return tokenSender.sendToken(user);
    } else {
      return {
        user: null,
        accessToken: null,
        refreshToken: null,
        error: {
          message: 'Invalid email or password',
        },
      };
    }
  }

  // compare password
  async comparePassword(
    password: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return await bcrypt.compare(password, hashedPassword);
  }

  // Get logged in user
  async getLoggedInUser(req: any) {
    const user = req.user;
    const accessToken = req.accesstoken;
    const refreshToken = req.refreshtoken;

    console.log({ user, accessToken, refreshToken });
    return { user, accessToken, refreshToken };
  }

  // Logout user
  async logout(req: any) {
    req.user = null;
    req.accessToken = null;
    req.refreshToken = null;

    return { message: 'Logout successfull' };
  }

  // Get all users

  async getUsers() {
    return this.prismaService.user.findMany({});
  }
}
