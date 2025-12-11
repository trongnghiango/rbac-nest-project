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
import { BYPASS_TRANSFORM_KEY } from '../decorators/bypass-transform.decorator';

@Injectable()
export class TransformResponseInterceptor<T> implements NestInterceptor<
  T,
  any
> {
  constructor(private reflector: Reflector) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // 1. Check xem có gắn cờ Bypass không
    const bypass = this.reflector.get<boolean>(
      BYPASS_TRANSFORM_KEY,
      context.getHandler(),
    );

    if (bypass) {
      return next.handle();
    }

    // 2. Logic bọc JSON bình thường
    return next.handle().pipe(
      map((data) => {
        // Double check: Nếu data là StreamableFile thì cũng không bọc
        if (data instanceof StreamableFile) {
          return data;
        }

        return {
          success: true,
          statusCode: context.switchToHttp().getResponse().statusCode,
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
