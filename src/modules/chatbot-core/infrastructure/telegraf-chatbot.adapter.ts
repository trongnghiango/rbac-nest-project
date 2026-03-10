import { Injectable } from '@nestjs/common';
import { InjectBot } from 'nestjs-telegraf';
import { Context, Telegraf } from 'telegraf';
import { IChatbotService } from '@core/shared/application/ports/chatbot.port';

@Injectable()
export class TelegrafChatbotAdapter implements IChatbotService {
    constructor(@InjectBot() private bot: Telegraf<Context>) { }

    async sendMessage(chatId: string, message: string): Promise<void> {
        await this.bot.telegram.sendMessage(chatId, message);
    }

    async sendPhoto(chatId: string, photoUrl: string, caption?: string): Promise<void> {
        await this.bot.telegram.sendPhoto(chatId, photoUrl, { caption });
    }
}
