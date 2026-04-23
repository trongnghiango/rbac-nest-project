import { Global, Module } from '@nestjs/common';
import { TelegrafModule } from 'nestjs-telegraf';
import { ConfigModule, ConfigService } from '@nestjs/config';
import * as https from 'https';
// ❌ XÓA IMPORT NÀY: import { session } from 'telegraf'; 
// ✅ Bỏ import * as, dùng require để bypass lỗi TypeScript
// eslint-disable-next-line @typescript-eslint/no-var-requires
const RedisSession = require('telegraf-session-redis');

import { AuthModule } from '../auth/auth.module';
import { AuthChatbotHandler } from '@modules/auth/infrastructure/chatbot/auth.chatbot';
import { IChatbotService } from '@core/shared/application/ports/chatbot.port';
import { TelegrafChatbotAdapter } from './infrastructure/telegraf-chatbot.adapter';
import { UserModule } from '@modules/user/user.module';

@Global()
@Module({
    imports: [
        TelegrafModule.forRootAsync({
            imports: [ConfigModule],
            useFactory: (configService: ConfigService) => {

                // 1. Lấy thông tin Redis từ config
                const uri = configService.get<string>('redis.uri');
                const host = configService.get<string>('redis.host');
                const port = configService.get<number>('redis.port');
                const password = configService.get<string>('redis.password');

                // 2. Khởi tạo cấu hình kết nối cho Redis Session
                let redisUrl = uri;
                if (!redisUrl) {
                    // Fallback tự build URL nếu dùng host/port (Local Docker)
                    redisUrl = password
                        ? `redis://:${password}@${host}:${port}`
                        : `redis://${host}:${port}`;
                }

                // 3. Khởi tạo Store Redis cho Telegraf
                const redisSession = new RedisSession({
                    store: { url: redisUrl },
                    property: 'session',
                    ttl: 86400, // Session hết hạn sau 1 ngày (tùy chỉnh)
                });

                // Tạo một HTTPS Agent để kết nối sống dai hơn và tránh timeout
                const agent = new https.Agent({
                    keepAlive: true,
                    keepAliveMsecs: 10000,
                });

                return {
                    token: configService.get<string>('TELEGRAM_BOT_TOKEN'),
                    // ✅ Thay session() bằng middleware của Redis
                    middlewares: [redisSession.middleware()],
                    options: {
                        telegram: {
                            agent: agent,
                            apiRoot: configService.get<string>('TELEGRAM_API_ROOT') || 'https://api.telegram.org'
                        }
                    }
                };
            },
            inject: [ConfigService],
        }),
        AuthModule,
        UserModule,
    ],
    providers: [
        AuthChatbotHandler,
        TelegrafChatbotAdapter,
        {
            provide: IChatbotService,
            useClass: TelegrafChatbotAdapter
        }
    ],
    exports: [TelegrafModule, IChatbotService],
})
export class ChatbotCoreModule { }
