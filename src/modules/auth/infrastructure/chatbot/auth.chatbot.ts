
import { Update, Ctx, Command } from 'nestjs-telegraf';
import { Context } from 'telegraf';
import { Injectable, Inject } from '@nestjs/common';
import { AuthenticationService } from '../../application/services/authentication.service';
// ✅ Import Symbol IUserRepository
import { IUserRepository } from '../../../user/domain/repositories/user.repository';

@Update()
@Injectable()
export class AuthChatbotHandler {
    constructor(
        private readonly authService: AuthenticationService,
        // ✅ Sửa lại dùng Symbol thay vì String
        @Inject(IUserRepository) private readonly userRepo: IUserRepository,
    ) { }

    @Command('login')
    async onLogin(@Ctx() ctx: Context) {
        // @ts-ignore
        const text = ctx.message?.text || '';
        const args = text.split(' ');

        // Cú pháp: /login <username> <password>
        if (args.length !== 3) {
            ctx.reply('⚠️ Cú pháp sai! Vui lòng nhập: /login <username> <password>');
            return;
        }

        const username = args[1];
        const password = args[2];
        const telegramId = String(ctx.from?.id);

        try {
            // ✅ Gọi hàm mới tạo ở Bước 1
            const user = await this.authService.validateCredentials(username, password);

            if (!user) {

                ctx.reply('❌ Tên đăng nhập hoặc mật khẩu không đúng.');

                return;
            }

            // ✅ Kiểm tra userRepo phải có hàm này
            if (this.userRepo.updateTelegramId) {
                await this.userRepo.updateTelegramId(String(user.id), telegramId);
                ctx.reply(`✅ Đăng nhập thành công! Xin chào ${user.fullName}.\nUser ID của bạn đã liên kết với Telegram này.`);
            } else {
                ctx.reply('❌ Lỗi hệ thống: Repository chưa hỗ trợ update Telegram ID.');
            }
            return;

        } catch (error) {
            console.error(error);
            ctx.reply('❌ Có lỗi xảy ra khi đăng nhập.');
            return;
        }
    }

    @Command('logout')
    async onLogout(@Ctx() ctx: Context) {
        const telegramId = String(ctx.from?.id);

        if (this.userRepo.removeTelegramId) {
            await this.userRepo.removeTelegramId(telegramId);
            ctx.reply('👋 Đã hủy liên kết tài khoản thành công.');
            return;
        }
        ctx.reply('❌ Lỗi hệ thống: Repository chưa hỗ trợ tính năng này.');
        return;
    }

    @Command('me')
    async onMe(@Ctx() ctx: Context) {
        const telegramId = String(ctx.from?.id);

        // ✅ Cần đảm bảo userRepo có hàm này
        const user = await this.userRepo.findByTelegramId?.(telegramId);

        if (!user) {
            await ctx.reply('❓ Bạn chưa đăng nhập. Dùng /login để bắt đầu.');
            return;
        }

        await ctx.reply(`👤 Thông tin:\n- Tên: ${user.fullName}\n- Username: ${user.username}\n- Role: ${user.roles || 'N/A'}`);
        return;
    }
}
