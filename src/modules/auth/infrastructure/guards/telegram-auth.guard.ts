import { CanActivate, ExecutionContext, Injectable, Inject } from '@nestjs/common';
import { TelegrafExecutionContext } from 'nestjs-telegraf';
import { Context } from 'telegraf';
// ✅ Import Symbol
import { IUserRepository } from '../../../user/domain/repositories/user.repository';

@Injectable()
export class TelegramAuthGuard implements CanActivate {
    constructor(
        // ✅ Dùng Symbol
        @Inject(IUserRepository) private readonly userRepo: IUserRepository,
    ) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const ctx = TelegrafExecutionContext.create(context);
        const telegramContext = ctx.getContext<Context>();
        const telegramId = String(telegramContext.from?.id);

        if (!telegramId || telegramId === 'undefined') return false;

        // ✅ Optional chaining phòng trường hợp repo chưa có hàm này
        const user = await this.userRepo.findByTelegramId?.(telegramId);

        if (!user) {
            await telegramContext.reply('⛔ Bạn chưa đăng nhập! Vui lòng dùng lệnh:\n/login <username> <password>');
            return false;
        }

        // Gắn user vào state để Handler sử dụng
        // Telegraf Context State
        (telegramContext as any).state = (telegramContext as any).state || {};
        (telegramContext as any).state.user = user;

        return true;
    }
}
