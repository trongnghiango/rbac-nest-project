import { Update, Ctx, Command } from 'nestjs-telegraf';
import { Context, Scenes } from 'telegraf';
import { UseGuards } from '@nestjs/common';
import { TelegramAuthGuard } from '../../../auth/infrastructure/guards/telegram-auth.guard'; // Import Guard vừa tạo
import { GetCaseDetailsQuery } from '../../application/queries/get-case-details.query';
import { User } from '@modules/user/domain/entities/user.entity';

@Update()
@UseGuards(TelegramAuthGuard) // 🔒 BẢO VỆ TOÀN BỘ HANDLER NÀY
export class DentalTreatmentChatbot {
    constructor(
        private readonly getCaseDetailsQuery: GetCaseDetailsQuery,
    ) { }

    @Command('case')
    async onGetCase(@Ctx() ctx: Context) {
        // 1. Lấy thông tin User hiện tại từ Context (do Guard gắn vào)
        // Ép kiểu về User Entity để có intellisense cho .id, .roles, .fullName
        const currentUser = (ctx as any).state.user as User;

        if (!currentUser) return; // Guard đã chặn rồi, nhưng check thêm cho chắc

        // 2. Parse Case ID từ tin nhắn
        // Safe access text message
        const messageText = 'text' in ctx.message ? ctx.message.text : '';
        const caseId = messageText.split(' ')[1]; // Lấy phần tử thứ 2 sau dấu cách

        if (!caseId) {
            await ctx.reply('⚠️ Vui lòng nhập Case ID. Ví dụ: /case 100');
            return;
        }

        // 3. Gọi Query (Lưu ý: tham số thứ 2 là 'CaseId' như đã sửa ở bước trước)
        const result = await this.getCaseDetailsQuery.execute(caseId, 'CaseId');

        if (!result) {
            await ctx.reply('❌ Không tìm thấy hồ sơ với ID này.');
            return;
        }

        // 4. KIỂM TRA QUYỀN SỞ HỮU (AUTHORIZATION)
        // Logic: Admin xem được hết. Bác sĩ chỉ xem được ca của mình.

        // Kiểm tra role (User entity mới dùng mảng roles)
        const isAdmin = currentUser.roles.includes('SUPER_ADMIN') || currentUser.roles.includes('ADMIN');

        // Kiểm tra sở hữu (So sánh tên bác sĩ hoặc ID bác sĩ)
        // Lưu ý: Tốt nhất DTO nên trả về dentistId để so sánh chính xác với currentUser.id
        // Ở đây tạm so sánh theo tên bác sĩ (tương đối)
        const isOwner = result.doctorName === currentUser.fullName;

        if (!isAdmin && !isOwner) {
            await ctx.reply('⛔ Bạn không có quyền truy cập vào hồ sơ này (Chỉ Bác sĩ phụ trách hoặc Admin).');
            return;
        }

        // 5. Trả về kết quả định dạng đẹp
        const dateStr = result.createdAt ? new Date(result.createdAt).toLocaleDateString('vi-VN') : 'N/A';

        await ctx.reply(
            `🦷 <b>THÔNG TIN HỒ SƠ #${result.caseId}</b>\n` +
            `--------------------------------\n` +
            `👤 <b>Bệnh nhân:</b> ${result.patientName}\n` +
            `🆔 <b>Mã BN:</b> ${result.patientCode}\n` +
            `👨‍⚕️ <b>Bác sĩ:</b> ${result.doctorName || 'Chưa phân công'}\n` +
            `🏥 <b>Phòng khám:</b> ${result.clinicName || 'N/A'}\n` +
            `📅 <b>Ngày tạo:</b> ${dateStr}`,
            { parse_mode: 'HTML' } // Cho phép in đậm
        );
    }

    @Command('upload')
    async onUpload(@Ctx() ctx: Scenes.SceneContext) {
        // Kiểm tra quyền (Chỉ Bác sĩ hoặc Admin mới được upload)
        const user = (ctx as any).state.user;
        // Logic check role user...

        await ctx.scene.enter('upload_aligner_scene');
    }

}
