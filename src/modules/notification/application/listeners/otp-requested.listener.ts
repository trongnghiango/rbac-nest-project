import { Injectable, Inject } from '@nestjs/common';
import { EventHandler } from '@core/shared/infrastructure/event-bus/decorators/event-handler.decorator';
import { OtpRequestedEvent } from '@modules/auth/domain/events/otp-requested.event';
import { IEmailSender } from '../ports/email-sender.port';
import { ILogger, LOGGER_TOKEN } from '@core/shared/application/ports/logger.port';

@Injectable()
export class OtpRequestedListener {
    constructor(
        @Inject(IEmailSender) private readonly emailSender: IEmailSender,
        @Inject(LOGGER_TOKEN) private readonly logger: ILogger,
    ) { }

    @EventHandler(OtpRequestedEvent)
    async handleOtpRequested(event: OtpRequestedEvent) {
        const { email, fullName, otpCode } = event.payload;

        this.logger.info(`📢 [EVENT RECEIVED] OtpRequested: Cấp mã OTP cho ${email}`);

        const subject = 'Mã xác thực đặt lại mật khẩu (OTP)';
        const body = `
      Xin chào ${fullName},
      
      Mã OTP để đặt lại mật khẩu của bạn là: ${otpCode}
      Mã này sẽ hết hạn trong 5 phút. Vui lòng không chia sẻ mã này cho bất kỳ ai.
    `;

        // Gửi email thông qua Port (ConsoleEmailAdapter sẽ in ra Terminal)
        await this.emailSender.send(email, subject, body);
    }
}
