import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';

import { UserModule } from '../user/user.module';
import { AuthenticationService } from './application/services/authentication.service';
import { JwtStrategy } from './infrastructure/strategies/jwt.strategy';
import { JwtAuthGuard } from './infrastructure/guards/jwt-auth.guard';
import { AuthController } from './infrastructure/controllers/auth.controller';
import { SessionOrmEntity } from './infrastructure/persistence/entities/session.orm-entity';
import { TypeOrmSessionRepository } from './infrastructure/persistence/typeorm-session.repository';

@Module({
  imports: [
    UserModule,
    TypeOrmModule.forFeature([SessionOrmEntity]),
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET') || 'super-secret-key',
        signOptions: { expiresIn: configService.get('JWT_EXPIRES_IN', '24h') },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthenticationService,
    JwtStrategy,
    JwtAuthGuard,
    {
      provide: 'ISessionRepository',
      useClass: TypeOrmSessionRepository,
    },
  ],
  exports: [JwtAuthGuard, AuthenticationService, JwtModule, PassportModule],
})
export class AuthModule {}
