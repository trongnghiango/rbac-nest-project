import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { Request, Response } from 'express';
import { UserDomainException } from '@modules/user/domain/exceptions/user-domain.exceptions';
import { PG_ERROR_CODES } from '@core/constants/pg-error-codes';

interface ErrorResponse {
  status: number;
  message: string;
  errorCode?: string;
  errors?: any;
}

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger('SystemError');
  private readonly isProduction = process.env.NODE_ENV === 'production';

  catch(exception: any, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    // 1. Trích xuất thông tin lỗi (Logic xử lý nằm riêng ở hàm dưới)
    const errorInfo = this.parseError(exception);

    // 2. Ghi log nếu là lỗi hệ thống (500)
    if (errorInfo.status === HttpStatus.INTERNAL_SERVER_ERROR) {
      this.logger.error(`[${request.method}] ${request.url}`, exception.stack);
    }

    // 3. Phản hồi JSON đồng nhất
    response.status(errorInfo.status).json({
      success: false,
      statusCode: errorInfo.status,
      errorCode: errorInfo.errorCode,
      message: errorInfo.message,
      errors: errorInfo.errors,
      path: request.url,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Bộ não của Filter: Chuyển đổi mọi loại Exception thành ErrorResponse chuẩn
   */
  private parseError(err: any): ErrorResponse {
    // 🛡️ Trường hợp: Lỗi HTTP của NestJS (400, 401, 404...)
    if (err instanceof HttpException) {
      const res = err.getResponse() as any;
      return {
        status: err.getStatus(),
        message: res.message || res.error || res,
        errors: res.message,
      };
    }

    // 🛡️ Trường hợp: Lỗi Nghiệp vụ (Domain Exception)
    if (err instanceof UserDomainException) {
      return {
        status: HttpStatus.BAD_REQUEST,
        message: err.message,
        errorCode: err.code,
      };
    }

    // 🛡️ TRƯỜNG HỢP: LỖI DATABASE (POSTGRES)
    if (err.code && typeof err.code === 'string') {
      return this.handleDatabaseError(err);
    }

    // 🛡️ Trường hợp mặc định: Lỗi hệ thống không xác định (500)
    return {
      status: HttpStatus.INTERNAL_SERVER_ERROR,
      message: this.isProduction ? 'Internal server error' : err.message,
      errorCode: 'INTERNAL_SERVER_ERROR',
    };
  }

  /**
   * Bộ điều hướng xử lý lỗi Database
   */
  private handleDatabaseError(err: any): ErrorResponse {
    // Danh sách các chiến lược xử lý lỗi dựa trên mã lỗi
    const handlerMap: Record<string, (e: any) => ErrorResponse> = {
      [PG_ERROR_CODES.UNIQUE_VIOLATION]: (e) => ({
        status: HttpStatus.CONFLICT,
        errorCode: 'DUPLICATE_ENTRY',
        message: this.formatDuplicateMessage(e.detail),
      }),

      [PG_ERROR_CODES.FOREIGN_KEY_VIOLATION]: (e) => ({
        status: HttpStatus.BAD_REQUEST,
        errorCode: 'REFERENCE_ERROR',
        message: 'Dữ liệu liên quan không tồn tại hoặc đang được sử dụng.',
      }),

      [PG_ERROR_CODES.NOT_NULL_VIOLATION]: (e) => ({
        status: HttpStatus.BAD_REQUEST,
        errorCode: 'MISSING_FIELD',
        message: `Trường dữ liệu [${e.column}] không được để trống.`,
      }),

      [PG_ERROR_CODES.INVALID_TEXT_REPRESENTATION]: (e) => ({
        status: HttpStatus.BAD_REQUEST,
        errorCode: 'INVALID_DATA_TYPE',
        message: 'Định dạng dữ liệu không hợp lệ.',
      }),
    };

    // Lấy handler tương ứng, nếu không có thì trả về lỗi hệ thống 500
    const handler = handlerMap[err.code];
    if (handler) return handler(err);

    return {
      status: HttpStatus.INTERNAL_SERVER_ERROR,
      message: this.isProduction ? 'Database processing error' : err.message,
      errorCode: 'DATABASE_ERROR',
    };
  }

  /**
   * Logic trích xuất tên trường bị trùng từ chuỗi "Key (email)=(...) already exists"
   */
  private formatDuplicateMessage(detail: string): string {
    const match = detail?.match(/\((.*?)\)/); // Lấy nội dung trong dấu ngoặc đầu tiên
    const field = match ? match[1] : 'dữ liệu';

    const fieldMap: Record<string, string> = {
      email: 'Email',
      username: 'Tên đăng nhập',
      employee_code: 'Mã nhân viên',
    };

    return `${fieldMap[field] || field} này đã tồn tại trên hệ thống.`;
  }

}
