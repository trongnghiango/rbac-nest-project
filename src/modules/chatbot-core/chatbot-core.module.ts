import { Global, Module } from '@nestjs/common';
import { TelegrafModule } from 'nestjs-telegraf';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { session } from 'telegraf'; // 👈 1. Import cái này

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
            useFactory: (configService: ConfigService) => ({
                token: configService.get<string>('TELEGRAM_BOT_TOKEN'),
                // 👇 2. BẮT BUỘC PHẢI CÓ DÒNG NÀY ĐỂ WIZARD CHẠY ĐƯỢC
                middlewares: [session()],
                options: {
                    telegram: {
                        // apiRoot phải nằm trong object 'telegram'
                        apiRoot: configService.get<string>('TELEGRAM_API_ROOT') || 'http://localhost:8081'
                    }
                }
            }),
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
