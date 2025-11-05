import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './service/auth.service';
import { JwtService } from '@nestjs/jwt';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from '../entities/user.entity';
import { ConfigService } from '@nestjs/config';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

describe('AuthService', () => {
  let service: AuthService;
  let userRepository: Repository<User>;
  let configService: ConfigService;
  let jwtService: JwtService;

  const mockUserRepository = {
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
    update: jest.fn(),
  };

  const mockConfigService = {
    get: jest.fn((key: string) => {
      if (key === 'BCRYPT_SALT_ROUNDS') return '10';
      if (key === 'JWT_SECRET') return 'secret';
      if (key === 'JWT_ACCESS_EXPIRATION') return '900';
      if (key === 'JWT_REFRESH_SECRET') return 'refresh_secret';
      if (key === 'JWT_REFRESH_EXPIRATION') return '604800';
      return null;
    }),
  };

  const mockJwtService = {
    sign: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: getRepositoryToken(User),
          useValue: mockUserRepository,
        },
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
        {
          provide: JwtService,
          useValue: mockJwtService,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
    configService = module.get<ConfigService>(ConfigService);
    jwtService = module.get<JwtService>(JwtService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('register', () => {
    it('should register a new user', async () => {
      const registerDto = {
        email: 'test@test.com',
        password: 'Password123!',
        name: 'Test User',
      };
      const hashedPassword = 'hashedPassword';
      const user = { id: '1', ...registerDto, password: hashedPassword, createdAt: new Date(), updatedAt: new Date() };

      mockUserRepository.findOne.mockResolvedValue(null);
      jest.spyOn(bcrypt, 'hash').mockResolvedValue(hashedPassword as never);
      mockUserRepository.create.mockReturnValue(user);
      mockUserRepository.save.mockResolvedValue(user);

      const result = await service.register(registerDto.email, registerDto.password, registerDto.name);

      expect(result).toEqual({
        id: user.id,
        email: user.email,
        name: user.name,
        createdAt: user.createdAt,
      });
    });
    it('should throw an error if email is already in use', async () => {
      const registerDto = {
        email: 'test@test.com',
        password: 'Password123!',
        name: 'Test User',
      };

      mockUserRepository.findOne.mockResolvedValue({ id: '1', ...registerDto });

      await expect(service.register(registerDto.email, registerDto.password, registerDto.name)).rejects.toThrow(
        'Email already in use',
      );
    });

    it('should throw an error if password is not secure', async () => {
      const registerDto = {
        email: 'test@test.com',
        password: '12345678',
        name: 'Test User',
      };

      await expect(service.register(registerDto.email, registerDto.password, registerDto.name)).rejects.toThrow(
        'Password must have at least 8 characters, including uppercase, lowercase, number, and symbol',
      );
    });
  });

  describe('login', () => {
    it('should login a user and return tokens', async () => {
      const loginDto = { email: 'test@test.com', password: 'Password123!' };
      const user = { id: '1', ...loginDto, name: 'Test User', refreshTokenHash: null, role: 'user' };
      const tokens = { accessToken: 'access_token', refreshToken: 'refresh_token' };

      mockUserRepository.findOne.mockResolvedValue(user);
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(true as never);
      mockJwtService.sign.mockReturnValueOnce(tokens.accessToken).mockReturnValueOnce(tokens.refreshToken);
      jest.spyOn(bcrypt, 'hash').mockResolvedValue('hashed_refresh_token' as never);

      const result = await service.login(loginDto);

      expect(result).toEqual(tokens);
    });

    it('should throw an error if user does not exist', async () => {
      const loginDto = { email: 'test@test.com', password: 'Password123!' };

      mockUserRepository.findOne.mockResolvedValue(null);

      await expect(service.login(loginDto)).rejects.toThrow('Invalid credentials');
    });

    it('should throw an error if password is not valid', async () => {
      const loginDto = { email: 'test@test.com', password: 'Password123!' };
      const user = { id: '1', ...loginDto, name: 'Test User' };

      mockUserRepository.findOne.mockResolvedValue(user);
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(false as never);

      await expect(service.login(loginDto)).rejects.toThrow('Invalid credentials');
    });
  });

  describe('logout', () => {
    it('should logout a user', async () => {
      const userId = '1';

      const result = await service.logout(userId);

      expect(mockUserRepository.update).toHaveBeenCalledWith(userId, { refreshTokenHash: null });
      expect(result).toEqual({ ok: true });
    });
  });

  describe('getUserProfile', () => {
    it('should return user profile', async () => {
      const userId = '1';
      const user = { id: userId, email: 'test@test.com', name: 'Test User' };

      mockUserRepository.findOne.mockResolvedValue(user);

      const result = await service.getUserProfile(userId);

      expect(result).toEqual(user);
    });

    it('should throw an error if user not found', async () => {
      const userId = '1';

      mockUserRepository.findOne.mockResolvedValue(null);

      await expect(service.getUserProfile(userId)).rejects.toThrow('User not found');
    });
  });

  describe('refreshTokens', () => {
    it('should refresh tokens', async () => {
      const userId = '1';
      const refreshToken = 'refresh_token';
      const user = { id: userId, email: 'test@test.com', name: 'Test User', refreshTokenHash: 'hashed_refresh_token', role: 'user' };
      const tokens = { accessToken: 'access_token', refreshToken: 'refresh_token' };

      mockUserRepository.findOne.mockResolvedValue(user);
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(true as never);
      jest.spyOn(service, 'login').mockResolvedValue(tokens);

      const result = await service.refreshTokens(userId, refreshToken);

      expect(result).toEqual(tokens);
    });

    it('should throw an error if user not found', async () => {
      const userId = '1';
      const refreshToken = 'refresh_token';

      mockUserRepository.findOne.mockResolvedValue(null);

      await expect(service.refreshTokens(userId, refreshToken)).rejects.toThrow('Invalid Token');
    });

    it('should throw an error if refresh token is invalid', async () => {
      const userId = '1';
      const refreshToken = 'refresh_token';
      const user = { id: userId, email: 'test@test.com', name: 'Test User', refreshTokenHash: 'hashed_refresh_token' };

      mockUserRepository.findOne.mockResolvedValue(user);
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(false as never);

      await expect(service.refreshTokens(userId, refreshToken)).rejects.toThrow('Invalid Token');
    });
  });
});

