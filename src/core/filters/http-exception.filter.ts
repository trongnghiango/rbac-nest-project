import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';

// 1. Định nghĩa Interface cho cấu trúc lỗi mặc định của NestJS
interface NestErrorResponse {
  statusCode: number;
  message: string | string[];
  error: string;
}

// 2. Định nghĩa Interface cho cấu trúc response trả về client
interface ApiResponse {
  success: boolean;
  statusCode: number;
  message: string;
  errors: string | string[] | null;
  path: string;
  timestamp: string;
}

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status = exception.getStatus
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;

    // 3. Lấy response gốc (có thể là string hoặc object)
    const exceptionResponse = exception.getResponse();

    // 4. Khởi tạo giá trị mặc định
    let message = 'Error';
    let errors: string | string[] | null = null;

    // 5. Xử lý Logic Type-Safe
    if (typeof exceptionResponse === 'string') {
      // Trường hợp 1: throw new BadRequestException('Lỗi gì đó')
      message = exceptionResponse;
    } else if (
      typeof exceptionResponse === 'object' &&
      exceptionResponse !== null
    ) {
      // Trường hợp 2: Lỗi từ class-validator hoặc NestJS chuẩn
      // Ép kiểu an toàn về Interface đã định nghĩa
      const responseObj = exceptionResponse as NestErrorResponse;

      // Logic cũ của bạn: Ưu tiên lấy 'error' làm message chính (VD: "Bad Request")
      // Nếu không có 'error', lấy 'message' (nếu nó là string)
      if (responseObj.error) {
        message = responseObj.error;
      } else if (typeof responseObj.message === 'string') {
        message = responseObj.message;
      }

      // 'errors' chứa chi tiết (VD: mảng các field validate sai)
      errors = responseObj.message || null;
    }

    // 6. Tạo response body theo Interface chuẩn
    const responseBody: ApiResponse = {
      success: false,
      statusCode: status,
      message: message,
      errors: errors,
      path: request.url,
      timestamp: new Date().toISOString(),
    };

    response.status(status).json(responseBody);
  }
}
