import { Wizard, WizardStep, Ctx } from 'nestjs-telegraf';
import { Scenes } from 'telegraf';
import { Inject, Injectable } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import axios from 'axios';
import { ConfigService } from '@nestjs/config';

// Domain Imports
import { UploadCaseUseCase } from '../../../application/use-cases/upload-case.use-case';
import { UploadCaseDto, ProductType } from '../../../application/dtos/upload-case.dto';
import { User } from '@modules/user/domain/entities/user.entity';
import { IPatientRepository } from '@modules/patient/domain/repositories/patient.repository';

// Interface State
interface UploadCaseState {
    caseData: Partial<UploadCaseDto>;
}

// Interface Context
interface UploadWizardContext extends Scenes.WizardContext {
    state: { user: User; };
}

@Wizard('upload_aligner_scene')
@Injectable()
export class UploadAlignerScene {
    constructor(
        private readonly uploadUseCase: UploadCaseUseCase,
        private readonly configService: ConfigService,
        @Inject(IPatientRepository) private readonly patientRepo: IPatientRepository,
    ) { }

    // --- BƯỚC 1: KHỞI TẠO ---
    @WizardStep(1)
    async onEnter(@Ctx() ctx: UploadWizardContext) {
        try {
            const currentUser = ctx.state.user;
            const wizardState = ctx.wizard.state as UploadCaseState;

            wizardState.caseData = {
                productType: ProductType.Aligner,
                clinicName: 'Telegram Upload',
                doctorName: currentUser?.fullName || 'Unknown Doctor',
            };

            await ctx.reply('🦷 <b>UPLOAD ALIGNER CASE</b>\nVui lòng nhập <b>Mã Bệnh Nhân</b>:', { parse_mode: 'HTML' });
            ctx.wizard.next();
        } catch (error) {
            console.error('Step 1 Error:', error);
            await ctx.scene.leave();
        }
    }

    // --- BƯỚC 2: NHẬN MÃ BỆNH NHÂN ---
    @WizardStep(2)
    async onCodeReceived(@Ctx() ctx: UploadWizardContext) {
        if (!ctx.message || !('text' in ctx.message)) return;
        const code = ctx.message.text.trim();
        const wizardState = ctx.wizard.state as UploadCaseState;
        wizardState.caseData.patientCode = code;

        try {
            const existing = await this.patientRepo.findPatientByCode(code);
            if (existing) {
                wizardState.caseData.patientName = existing.fullName;
                await ctx.reply(`✅ Tìm thấy: ${existing.fullName}\n📂 Vui lòng gửi <b>File ZIP</b>:`, { parse_mode: 'HTML' });
                ctx.wizard.selectStep(3); // Nhảy tới bước 4
            } else {
                await ctx.reply(`🆕 Nhập tên bệnh nhân mới:`);
                ctx.wizard.next();
            }
        } catch (error) {
            await ctx.reply('❌ Lỗi kiểm tra mã bệnh nhân.');
            await ctx.scene.leave();
        }
    }

    // --- BƯỚC 3: NHẬN TÊN (NẾU MỚI) ---
    @WizardStep(3)
    async onNameReceived(@Ctx() ctx: UploadWizardContext) {
        if (!ctx.message || !('text' in ctx.message)) return;
        const wizardState = ctx.wizard.state as UploadCaseState;
        wizardState.caseData.patientName = ctx.message.text.trim();
        await ctx.reply(`📂 Đã lưu tên. Vui lòng gửi <b>File ZIP</b>:`, { parse_mode: 'HTML' });
        ctx.wizard.next();
    }

    // --- BƯỚC 4: NHẬN FILE VÀ XỬ LÝ (QUAN TRỌNG) ---
    @WizardStep(4)
    async onFileReceived(@Ctx() ctx: UploadWizardContext) {
        try {
            if (!ctx.message || !('document' in ctx.message)) {
                await ctx.reply('❌ Vui lòng gửi file đính kèm (Document).');
                return;
            }

            const doc = ctx.message.document;
            const { file_id, file_name, mime_type } = doc;

            if (!file_name?.toLowerCase().match(/\.(zip|rar)$/)) {
                await ctx.reply('❌ Chỉ chấp nhận file .zip hoặc .rar');
                return;
            }

            await ctx.reply('⏳ Đang xử lý file lớn (Direct Disk Access)...');

            // 1. Lấy đường dẫn tuyệt đối từ Telegram Local Server
            // VD trả về: /var/lib/telegram-bot-api/<TOKEN>/documents/file.zip
            const fileInfo = await ctx.telegram.getFile(file_id);
            const dockerPath = fileInfo.file_path;

            // 2. Chuyển đổi đường dẫn Docker -> Đường dẫn Máy thật (Host)
            // Trong Docker, thư mục gốc là: /var/lib/telegram-bot-api
            // Ở máy thật, thư mục gốc là biến env: TELEGRAM_LOCAL_ROOT
            const hostRoot = this.configService.get<string>('TELEGRAM_LOCAL_ROOT');

            if (!hostRoot) {
                throw new Error('Chưa cấu hình TELEGRAM_LOCAL_ROOT trong .env');
            }

            // Logic replace: Thay '/var/lib/telegram-bot-api' bằng '/home/user/.../telegram-data'
            const realFilePath = dockerPath.replace('/var/lib/telegram-bot-api', hostRoot);

            console.log(`📂 Reading file from: ${realFilePath}`);

            if (!fs.existsSync(realFilePath)) {
                // Đợi một chút vì có thể Docker chưa kịp sync file ra ổ cứng host
                await new Promise(res => setTimeout(res, 2000));
                if (!fs.existsSync(realFilePath)) {
                    throw new Error(`Không tìm thấy file trên ổ cứng: ${realFilePath}. Hãy kiểm tra cấu hình Volume Docker.`);
                }
            }

            // 3. Setup thư mục đích
            const uploadDir = this.configService.get<string>('dental.uploadDir') || 'uploads/dental/temp';
            if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

            const tempFilePath = path.join(uploadDir, `tele_${Date.now()}_${file_name}`);

            // 4. COPY file từ thư mục share sang thư mục upload của App
            // Dùng copy thay vì move để an toàn
            await fs.promises.copyFile(realFilePath, tempFilePath);

            console.log(`✅ File copied to: ${tempFilePath}`);

            // 5. Mock Multer & Gọi UseCase
            const mockMulterFile: Express.Multer.File = {
                fieldname: 'file',
                originalname: file_name || 'unknown.zip',
                encoding: '7bit',
                mimetype: mime_type || 'application/zip',
                destination: uploadDir,
                filename: path.basename(tempFilePath),
                path: tempFilePath,
                size: doc.file_size || 0,
                stream: fs.createReadStream(tempFilePath),
                buffer: Buffer.alloc(0),
            };

            const wizardState = ctx.wizard.state as UploadCaseState;
            const dto = wizardState.caseData as UploadCaseDto;
            dto.overwrite = 'false';

            const result = await this.uploadUseCase.execute(mockMulterFile, dto);

            await ctx.reply(
                `🎉 <b>UPLOAD THÀNH CÔNG!</b>\n` +
                `--------------------------\n` +
                `🆔 Case ID: <b>${result.caseId}</b>\n` +
                `👤 Bệnh nhân: ${dto.patientName}\n` +
                `⚙️ Trạng thái: <i>${result.status}</i>`,
                { parse_mode: 'HTML' }
            );

        } catch (error: any) {
            console.error('Tele Upload Err:', error);
            await ctx.reply(`❌ Lỗi xử lý: ${error.message}`);
        }

        await ctx.scene.leave();
    }
}
