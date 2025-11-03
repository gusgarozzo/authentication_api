import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/entities/user.entity';
import { ConfigService } from '@nestjs/config';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { JwtPayload } from '../interfaces/jwtPayload.interface';
import { LoginDto } from '../dto/login.dto';
import { IGeneratedTokens } from '../interfaces/generatedTokens.interface';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly saltRounds: number;
  private readonly secretKey: string;
  private readonly tokenExpiration: number;
  private readonly refreshTokenExpiration: number;
  private readonly refreshTokenSecret: string;

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {
    this.saltRounds = parseInt(
      this.configService.get<string>('BCRYPT_SALT_ROUNDS') || '10',
      10,
    );
    this.secretKey = this.configService.get<string>('JWT_SECRET') as string;
    this.tokenExpiration = parseInt(
      this.configService.get<string>('JWT_ACCESS_EXPIRATION') || '900',
      10,
    );
    this.refreshTokenSecret = this.configService.get<string>(
      'JWT_REFRESH_SECRET',
    ) as string;
    this.refreshTokenExpiration = parseInt(
      this.configService.get<string>('JWT_REFRESH_EXPIRATION') || '604800',
      10,
    );
  }

  async register(
    email: string,
    password: string,
    name: string,
  ): Promise<{
    id: string;
    email: string;
    name?: string;
    createdAt: Date;
  }> {
    try {
      const normalizedEmail = (email || '').trim().toLowerCase();
      if (!normalizedEmail || !password || password.length < 6) {
        throw new BadRequestException(
          'Invalid email or password (length must be at least 6 characters)',
        );
      }

      const exists = await this.userRepository.findOne({ where: { email } });
      if (exists) throw new BadRequestException('Email already in use');

      const hashed = await bcrypt.hash(password, this.saltRounds);

      const user = this.userRepository.create({
        email: normalizedEmail,
        password: hashed,
        name,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const saved = await this.userRepository.save(user);
      return {
        id: saved.id,
        email: saved.email,
        name: saved.name,
        createdAt: saved.createdAt,
      };
    } catch (error) {
      this.logger.error(
        `Error registering user: ${error.message}`,
        error.stack,
      );
      throw error;
    }
  }

  async validateUser(email: string, password: string): Promise<User | null> {
    try {
      const user = await this.userRepository.findOne({ where: { email } });
      if (!user) return null;

      const valid = await bcrypt.compare(password, user.password);

      return valid ? user : null;
    } catch (error) {
      this.logger.error(`Error validating user: ${error.message}`, error.stack);
      throw error;
    }
  }

  async login({ email, password }: LoginDto): Promise<IGeneratedTokens> {
    try {
      const user: User | null = await this.userRepository.findOne({
        where: { email: email },
      });

      if (!user) throw new UnauthorizedException('Invalid credentials');

      const valid = await bcrypt.compare(password, user.password);
      if (!valid) throw new UnauthorizedException('Invalid credentials');

      const tokens: IGeneratedTokens = await this.generateTokens(user);

      return tokens;
    } catch (error) {
      this.logger.error(`Error logging user in: ${error.message}`, error.stack);
      throw error;
    }
  }

  private async generateTokens(user: User): Promise<IGeneratedTokens> {
    try {
      const payload: JwtPayload = {
        sub: user.id,
        email: user.email,
        role: user.role,
      };

      const { accessToken, refreshToken } = this.getJwtSignedTokens(payload);

      await this.hashRefreshTokenAndUpdateRegister(refreshToken, user);

      return {
        accessToken,
        refreshToken,
      };
    } catch (error) {
      this.logger.error(
        `Error generating tokens: ${error.message}`,
        error.stack,
      );
      throw error;
    }
  }

  private async hashRefreshTokenAndUpdateRegister(
    refreshToken: string,
    user: User,
  ): Promise<void> {
    try {
      const hashedRefreshToken = await bcrypt.hash(
        refreshToken,
        this.saltRounds,
      );

      await this.userRepository.update(user.id, {
        refreshTokenHash: hashedRefreshToken,
        lastLogin: new Date(),
      });
    } catch (error) {
      this.logger.error(
        `Error hashing refresh token: ${error.message}`,
        error.stack,
      );
      throw error;
    }
  }

  private getJwtSignedTokens(payload: JwtPayload): IGeneratedTokens {
    try {
      const accessToken = this.jwtService.sign<JwtPayload>(payload, {
        secret: this.secretKey,
        expiresIn: this.tokenExpiration,
      });

      const refreshToken = this.jwtService.sign<JwtPayload>(payload, {
        secret: this.refreshTokenSecret,
        expiresIn: this.refreshTokenExpiration,
      });

      return { accessToken, refreshToken };
    } catch (error) {
      this.logger.error(
        `Error at jwt sign service: ${error.message}`,
        error.stack,
      );
      throw error;
    }
  }

  async refreshTokens(userId: string, refreshToken: string) {
    try {
      const user = await this.userRepository.findOne({ where: { id: userId } });
      if (!user || !user.refreshTokenHash) {
        throw new UnauthorizedException('Invalid Token');
      }

      const valid = await bcrypt.compare(refreshToken, user.refreshTokenHash);
      if (!valid) throw new UnauthorizedException('Invalid Token');

      return this.login(user);
    } catch (error) {
      this.logger.error(
        `Error refreshing token: ${error.message}`,
        error.stack,
      );
      throw error;
    }
  }

  async logout(userId: string): Promise<{ ok: Boolean }> {
    try {
      await this.userRepository.update(userId, { refreshTokenHash: null });
      return { ok: true };
    } catch (error) {
      this.logger.error(`Error logging out: ${error.message}`, error.stack);
      throw error;
    }
  }

  async getUserProfile(userId: string): Promise<User> {
    try {
      const user = await this.userRepository.findOne({
        where: { id: userId },
        select: ['id', 'email', 'name', 'isActive', 'createdAt'],
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      return user;
    } catch (error) {
      this.logger.error(
        `Error getting user profile: ${error.message}`,
        error.stack,
      );
      throw error;
    }
  }
}
