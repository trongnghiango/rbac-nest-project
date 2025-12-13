import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  StreamableFile,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { Response } from 'express'; // Nhớ import Response từ express
import { BYPASS_TRANSFORM_KEY } from '../decorators/bypass-transform.decorator';

// 1. Định nghĩa Interface cho object trả về để kiểm soát kiểu dữ liệu
export interface AppResponse<T> {
  success: boolean;
  statusCode: number;
  message: string;
  result: T;
}

@Injectable()
export class TransformResponseInterceptor<T> implements NestInterceptor<
  T,
  AppResponse<T> | StreamableFile
> {
  constructor(private reflector: Reflector) {}

  intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Observable<AppResponse<T> | StreamableFile> {
    const bypass = this.reflector.get<boolean>(
      BYPASS_TRANSFORM_KEY,
      context.getHandler(),
    );

    if (bypass) {
      return next.handle() as Observable<AppResponse<T> | StreamableFile>;
    }

    return next.handle().pipe(
      // FIX LỖI Ở ĐÂY:
      // Thay vì map((data) => ...), ta khai báo map((data: T) => ...)
      // TypeScript sẽ hiểu data có kiểu T, không phải any.
      map((data: T) => {
        // Double check: Nếu data là StreamableFile thì return luôn
        if (data instanceof StreamableFile) {
          return data;
        }

        // Lấy Response object từ Express để lấy statusCode chính xác
        const response = context.switchToHttp().getResponse<Response>();
        const status = response.statusCode;

        return {
          success: true,
          statusCode: status,
          message:
            this.reflector.get<string>(
              'response_message',
              context.getHandler(),
            ) || 'Success',
          result: data, // Lúc này việc gán data (T) vào result là an toàn
        };
      }),
    );
  }
}
