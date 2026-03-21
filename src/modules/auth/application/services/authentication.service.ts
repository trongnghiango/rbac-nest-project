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
import { OtpRequestedEvent } from '@modules/auth/domain/events/otp-requested.event';
import { ConfigService } from '@nestjs/config';

export type AuthResponse = {
  accessToken: string;
  refreshToken: string;
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
    private readonly configService: ConfigService,
  ) { }

  // =========================================================================
  // 1. NÂNG CẤP LOGIN (Lưu vào DB + Redis)
  // =========================================================================
  async login(credentials: {
    username: string;
    password: string;
    ip?: string;
    userAgent?: string;
  }): Promise<AuthResponse> {
    // 1. Tìm và kiểm tra User cơ bản
    const user = await this.userRepository.findByUsername(credentials.username);

    // Gộp check để tránh "Timing Attack" và code gọn hơn
    if (!user || !user.isActive || !user.hashedPassword) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // 2. Xác thực mật khẩu
    const isValid = await PasswordUtil.compare(credentials.password, user.hashedPassword);
    if (!isValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Đảm bảo ID tồn tại (Type guard cho TypeScript)
    if (user.id === undefined) {
      throw new InternalServerErrorException('User ID is missing');
    }

    // 3. Chuẩn bị Payload
    const payload: JwtPayload = {
      sub: user.id,
      username: user.username,
      roles: user.roles || []
    };

    // 4. Tạo Tokens song song (Không cần await từng cái vì là hàm đồng bộ của thư viện)
    const accessToken = this.jwtService.sign(payload);
    const refreshToken = this.jwtService.sign(
      { sub: user.id },
      { expiresIn: this.configService.get('auth.refreshTokenExpiresIn') }
    );

    // 5. Tính toán thời gian hết hạn đồng bộ cho DB
    // Chuyển đổi chuỗi "7d" hoặc "1d" từ config thành đối tượng Date
    const rtExpiresIn = this.configService.get<string>('auth.refreshTokenExpiresIn');
    const expiresAt = this.calculateExpiryDate(rtExpiresIn);

    // 6. Khởi tạo Entity Session
    const session = new Session({
      userId: user.id,
      token: accessToken,
      refreshToken: refreshToken,
      expiresAt: expiresAt,
      ipAddress: credentials.ip,
      userAgent: credentials.userAgent,
      createdAt: new Date(),
    });

    // 7. 🔥 THỰC THI SONG SONG: Lưu DB và Lưu Redis
    const sessionTtl = this.configService.get<number>('auth.sessionTtl');
    const redisKey = `auth:session:${accessToken}`;

    await Promise.all([
      this.sessionRepository.create(session),
      this.cacheService.set(redisKey, { userId: user.id }, sessionTtl)
    ]);

    return {
      accessToken,
      refreshToken,
      user: user.toJSON()
    };
  }

  /**
   * Hàm hỗ trợ tính toán ngày hết hạn từ chuỗi string (VD: "7d", "24h")
   */
  private calculateExpiryDate(expiresIn: string): Date {
    const amount = parseInt(expiresIn);
    const unit = expiresIn.slice(-1).toLowerCase();
    const date = new Date();

    switch (unit) {
      case 'd': date.setDate(date.getDate() + amount); break;
      case 'h': date.setHours(date.getHours() + amount); break;
      case 'm': date.setMinutes(date.getMinutes() + amount); break;
      default: date.setDate(date.getDate() + 1); // Mặc định 1 ngày
    }
    return date;
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
    // 1. Kiểm tra sự tồn tại của User (Nên check cả username và email)
    const existing = await this.userRepository.findByUsername(data.username);
    if (existing) throw new BadRequestException('User already exists');

    // 2. Hash mật khẩu
    const hashedPassword = await PasswordUtil.hash(data.password);

    // 3. Khởi tạo Entity User (Sử dụng Object Pattern như đã thống nhất)
    const newUser = new User({
      username: data.username,
      email: data.email,
      hashedPassword: hashedPassword,
      fullName: data.fullName,
      isActive: true,
      roles: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    // 4. Chạy Transaction
    const result = await this.txManager.runInTransaction(async (tx) => {
      // A. Lưu User
      const savedUser = await this.userRepository.save(newUser, tx);
      if (!savedUser.id) {
        throw new InternalServerErrorException('Failed to generate User ID');
      }

      // B. Tạo Tokens dựa trên Config
      const payload: JwtPayload = {
        sub: savedUser.id,
        username: savedUser.username,
        roles: [],
      };

      const accessToken = this.jwtService.sign(payload);
      const refreshToken = this.jwtService.sign(
        { sub: savedUser.id },
        { expiresIn: this.configService.get('auth.refreshTokenExpiresIn') }
      );

      // C. Tính toán ngày hết hạn cho Session DB (Đồng bộ với RT)
      const rtExpiresIn = this.configService.get<string>('auth.refreshTokenExpiresIn');
      const expiresAt = this.calculateExpiryDate(rtExpiresIn);

      // D. Lưu Session vào Database
      const session = new Session({
        userId: savedUser.id,
        token: accessToken,
        refreshToken: refreshToken,
        expiresAt: expiresAt,
        createdAt: new Date(),
      });

      await this.sessionRepository.create(session, tx);

      return { savedUser, accessToken, refreshToken };
    });

    // 5. 🔥 CÔNG VIỆC SAU TRANSACTION (Post-Transaction)

    // A. Lưu vào Redis để User có thể sử dụng ngay lập tức
    const sessionTtl = this.configService.get<number>('auth.sessionTtl');
    await this.cacheService.set(
      `auth:session:${result.accessToken}`,
      { userId: result.savedUser.id },
      sessionTtl
    );

    // B. Bắn Event thông báo (Không await nếu không cần thiết để tăng tốc phản hồi)
    this.eventBus.publish(
      new UserCreatedEvent(String(result.savedUser.id), { user: result.savedUser }),
    ).catch(err => this.logger.error('Failed to publish UserCreatedEvent', err));

    this.logger.info(`User registered successfully: ${result.savedUser.username}`);

    return {
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      user: result.savedUser.toJSON()
    };
  }

  // =========================================================================
  // 4. ĐỔI MẬT KHẨU (Dành cho User đang đăng nhập)
  // =========================================================================
  async changePassword(userId: number, dto: any): Promise<void> {
    const user = await this.userRepository.findById(userId);
    if (!user || !user.hashedPassword) throw new BadRequestException('User không hợp lệ');

    // Kiểm tra mật khẩu cũ
    const isMatch = await PasswordUtil.compare(dto.oldPassword, user.hashedPassword);
    if (!isMatch) throw new BadRequestException('Mật khẩu cũ không chính xác');

    // Hash mật khẩu mới và gọi hàm của Rich Domain Entity
    const hashedNew = await PasswordUtil.hash(dto.newPassword);
    user.changePassword(hashedNew); // Logic đổi trạng thái nằm gọn trong Entity

    await this.txManager.runInTransaction(async (tx) => {
      // 1. Lưu user
      await this.userRepository.save(user, tx);

      // 2. Bảo mật: Xóa toàn bộ Session cũ trong DB để ép các thiết bị khác văng ra (Đăng xuất khỏi mọi nơi)
      await this.sessionRepository.deleteByUserId(userId);
    });
  }

  // =========================================================================
  // 5. QUÊN MẬT KHẨU (Gửi OTP)
  // =========================================================================
  async forgotPassword(email: string): Promise<void> {
    const user = await this.userRepository.findByEmail(email);

    // Bảo mật: Không ném lỗi NotFound để tránh hacker dò quét email trong hệ thống
    if (!user || !user.isActive) return;

    // Sinh OTP 6 số ngẫu nhiên
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();

    // Lưu vào Redis (TTL 5 phút = 300 giây)
    const redisKey = `auth:otp:${email}`;
    await this.cacheService.set(redisKey, otpCode, 300);

    // Bắn Event để NotificationModule lo việc gửi Email
    await this.eventBus.publish(
      new OtpRequestedEvent(email, {
        email: user.email!,
        fullName: user.fullName || 'Người dùng',
        otpCode: otpCode,
      })
    );
  }

  // =========================================================================
  // 6. ĐẶT LẠI MẬT KHẨU (Xác thực OTP)
  // =========================================================================
  async resetPassword(dto: any): Promise<void> {
    const redisKey = `auth:otp:${dto.email}`;
    const cachedOtp = await this.cacheService.get<string>(redisKey);

    if (!cachedOtp || cachedOtp !== dto.otp) {
      throw new BadRequestException('Mã OTP không hợp lệ hoặc đã hết hạn');
    }

    const user = await this.userRepository.findByEmail(dto.email);
    if (!user) throw new BadRequestException('User không tồn tại');

    // Cập nhật mật khẩu mới
    const hashedNew = await PasswordUtil.hash(dto.newPassword);
    user.changePassword(hashedNew);

    await this.txManager.runInTransaction(async (tx) => {
      await this.userRepository.save(user, tx);
      await this.sessionRepository.deleteByUserId(user.id); // Xóa session cũ
    });

    // Hủy OTP trong Redis sau khi dùng thành công
    await this.cacheService.del(redisKey);
  }

}
