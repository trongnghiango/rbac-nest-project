import {
  Injectable,
  Inject,
  UnauthorizedException,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { IUserRepository } from '@modules/user/domain/repositories/user.repository';
import { ISessionRepository } from '../../domain/repositories/session.repository';
import { ITransactionManager } from '@core/shared/application/ports/transaction-manager.port';
import { PasswordUtil } from '@core/shared/utils/password.util';
import { User } from '@modules/user/domain/entities/user.entity';
import { Session } from '../../domain/entities/session.entity';
import { JwtPayload } from '@core/shared/types/common.types';
import { IEventBus } from '@core/shared/application/ports/event-bus.port';
import { UserCreatedEvent } from '@modules/user/domain/events/user-created.event';
import {
  type ILogger,
  LOGGER_TOKEN,
} from '@core/shared/application/ports/logger.port';
import { RegisterDto } from '../../infrastructure/dtos/auth.dto';
import { ICacheService } from '@core/shared/application/ports/cache.port';

export type AuthResponse = {
  accessToken: string;
  user: ReturnType<User['toJSON']>;
};

@Injectable()
export class AuthenticationService {
  constructor(
    @Inject(IUserRepository) private userRepository: IUserRepository,
    @Inject(ISessionRepository) private sessionRepository: ISessionRepository,
    @Inject(ITransactionManager) private txManager: ITransactionManager,
    @Inject(IEventBus) private eventBus: IEventBus,
    @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
    @Inject(ICacheService) private readonly cacheService: ICacheService,
    private jwtService: JwtService,
  ) { }

  // =========================================================================
  // 1. NÂNG CẤP LOGIN (Lưu vào DB + Redis)
  // =========================================================================
  async login(credentials: { username: string; password: string; ip?: string; userAgent?: string; }): Promise<AuthResponse> {
    const user = await this.userRepository.findByUsername(credentials.username);

    if (!user || !user.isActive) throw new UnauthorizedException('Invalid credentials');
    if (!user.hashedPassword) throw new UnauthorizedException('Password not set');

    const isValid = await PasswordUtil.compare(credentials.password, user.hashedPassword);
    if (!isValid) throw new UnauthorizedException('Invalid credentials');
    if (!user.id) throw new InternalServerErrorException('User ID is missing');

    const payload: JwtPayload = { sub: user.id, username: user.username, roles: [] };
    const accessToken = this.jwtService.sign(payload);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 1); // Token sống 1 ngày

    // A. Lưu vào Database (PostgreSQL)
    const session = new Session(undefined, user.id, accessToken, expiresAt, credentials.ip, credentials.userAgent, new Date());
    await this.sessionRepository.create(session);

    // B. 👉 Lưu vào Redis (Tính TTL theo giây để Redis tự động xóa khi hết hạn)
    const ttlInSeconds = Math.floor((expiresAt.getTime() - Date.now()) / 1000);
    const redisKey = `auth:session:${accessToken}`;
    // Lưu một object nhỏ (chứa userId) để tăng tốc độ truy xuất sau này
    await this.cacheService.set(redisKey, { userId: user.id }, ttlInSeconds);

    return { accessToken, user: user.toJSON() };
  }

  // =========================================================================
  // 2. NÂNG CẤP LOGOUT (Xóa khỏi DB + Redis)
  // =========================================================================
  async logout(token: string): Promise<void> {
    const redisKey = `auth:session:${token}`;

    // Xóa song song trên cả 2 hệ thống để tối ưu tốc độ
    await Promise.all([
      this.cacheService.del(redisKey),             // Xóa Cache
      this.sessionRepository.deleteByToken(token)  // Xóa DB
    ]);
  }

  // =========================================================================
  // 3. THÊM HÀM MỚI: KIỂM TRA TOKEN (Redis -> DB -> Restore Redis)
  // =========================================================================
  async validateTokenAndGetUserId(token: string): Promise<number | null> {
    const redisKey = `auth:session:${token}`;

    // LỚP 1: TÌM TRONG REDIS (Tốc độ mili-giây)
    const cachedSession = await this.cacheService.get<{ userId: number }>(redisKey);
    if (cachedSession) {
      return cachedSession.userId; // Trả về luôn, kết thúc hành trình!
    }

    // LỚP 2: NẾU REDIS KHÔNG CÓ (Có thể do Redis bị restart/clear cache) -> MÒ XUỐNG DB
    const session = await this.sessionRepository.findByToken(token);
    if (!session || session.isExpired()) {
      return null; // Token sai, đã bị xóa hoặc hết hạn
    }

    // LỚP 3: PHỤC HỒI LẠI CACHE (Warming Cache)
    // Để các request mili-giây tiếp theo của user này không cần xuống DB nữa
    const ttlInSeconds = Math.floor((session.expiresAt.getTime() - Date.now()) / 1000);
    if (ttlInSeconds > 0) {
      await this.cacheService.set(redisKey, { userId: session.userId }, ttlInSeconds);
    }

    return session.userId;
  }

  // ✅ THÊM HÀM NÀY CHO CHATBOT
  async validateCredentials(username: string, password: string): Promise<User | null> {
    // 1. Tìm user (Lưu ý: LoginDto của bạn dùng username, Chatbot đang nhập email -> Cần thống nhất)
    // Ở đây mình giả định dùng username cho khớp hệ thống
    const user = await this.userRepository.findByUsername(username);

    if (!user || !user.isActive || !user.hashedPassword) return null;

    // 2. Check pass
    const isValid = await PasswordUtil.compare(password, user.hashedPassword);

    return isValid ? user : null;
  }

  async validateUser(
    payload: JwtPayload,
  ): Promise<ReturnType<User['toJSON']> | null> {
    const user = await this.userRepository.findById(payload.sub);
    if (!user || !user.isActive) return null;
    return user.toJSON();
  }

  async register(data: RegisterDto): Promise<AuthResponse> {
    const existing = await this.userRepository.findByUsername(data.username);
    if (existing) throw new BadRequestException('User already exists');

    const hashedPassword = await PasswordUtil.hash(data.password);

    const newUser = new User(
      data.id,
      data.username,
      data.email,
      hashedPassword,
      data.fullName,
      true,
      [],
      undefined,
      undefined,
      undefined,
      undefined,
      new Date(),
      new Date(),
    );

    return this.txManager.runInTransaction(async (tx) => {
      const savedUser = await this.userRepository.save(newUser, tx);
      if (!savedUser.id)
        throw new InternalServerErrorException('Failed to generate User ID');

      this.logger.info('Register:::');

      const payload: JwtPayload = {
        sub: savedUser.id,
        username: savedUser.username,
        roles: [],
      };
      const accessToken = this.jwtService.sign(payload);

      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 1);

      const session = new Session(
        undefined,
        savedUser.id,
        accessToken,
        expiresAt,
        undefined,
        undefined,
        new Date(),
      );

      await this.sessionRepository.create(session, tx);

      // Publish Event inside transaction (or use Outbox pattern for better reliability)
      await this.eventBus.publish(
        new UserCreatedEvent(String(savedUser.id), { user: savedUser }),
      );

      return { accessToken, user: savedUser.toJSON() };
    });
  }

}
