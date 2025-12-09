import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status = exception.getStatus
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;

    const exceptionResponse: any = exception.getResponse();
    const errorMsg = exceptionResponse.message;

    const responseBody = {
      success: false,
      statusCode: status,
      message: typeof exceptionResponse === 'string' ? exceptionResponse : 'Error',
      errors: errorMsg || null,
      path: request.url,
      timestamp: new Date().toISOString(),
    };

    if (typeof exceptionResponse === 'object' && exceptionResponse !== null) {
      responseBody.message = exceptionResponse['error'] || exceptionResponse['message'];
      responseBody.errors = exceptionResponse['message'];
    }

    response.status(status).json(responseBody);
  }
}
