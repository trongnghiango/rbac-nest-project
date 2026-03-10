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
import { Response } from 'express';
import { BYPASS_TRANSFORM_KEY } from '../decorators/bypass-transform.decorator';

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
  constructor(private reflector: Reflector) { }

  intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Observable<AppResponse<T> | StreamableFile> {

    // 🛑 FIX: Chỉ áp dụng Interceptor này cho HTTP Request
    // Nếu là 'rpc' (Microservice) hoặc ngữ cảnh của Telegraf, thì bỏ qua (return luôn)
    if (context.getType() !== 'http') {
      return next.handle();
    }

    const bypass = this.reflector.get<boolean>(
      BYPASS_TRANSFORM_KEY,
      context.getHandler(),
    );

    if (bypass) {
      return next.handle() as Observable<AppResponse<T> | StreamableFile>;
    }

    return next.handle().pipe(
      map((data: T) => {
        if (data instanceof StreamableFile) {
          return data;
        }

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
          result: data,
        };
      }),
    );
  }
}
