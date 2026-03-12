import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: any, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    let message = 'Internal server error';
    let errors = null;

    // ✅ Kiểm tra môi trường
    const isProduction = process.env.NODE_ENV === 'production';

    if (exception instanceof HttpException) {
      const res: any = exception.getResponse();
      message =
        typeof res === 'string' ? res : res.message || res.error || message;
      errors = res.message || null;
    } else {
      // 🚨 Đây là lỗi hệ thống (Database, Runtime Exception, v.v.)
      console.error('🔥 System Error:', exception); // Ghi log ra Winston

      // ✅ BẢO MẬT: Ẩn chi tiết lỗi nếu đang ở Production
      if (isProduction) {
        message = 'Internal server error. Please try again later.';
      } else {
        // Chỉ hiện lỗi thật lúc code (Development)
        message = exception.message || 'Database Transaction Error';
      }
    }

    response.status(status).json({
      success: false,
      statusCode: status,
      message: message,
      errors: errors,
      path: request.url,
      timestamp: new Date().toISOString(),
    });
  }
}
