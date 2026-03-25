import type { ErrorResponse } from '@aegisai/shared';
import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger
} from '@nestjs/common';
import type { Response } from 'express';

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GlobalExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const response = host.switchToHttp().getResponse<Response>();
    const { status, message, errorCode } = this.normalizeException(exception);
    const payload: ErrorResponse = {
      success: false,
      data: null,
      message,
      errorCode,
      timestamp: new Date().toISOString()
    };

    if (status >= HttpStatus.INTERNAL_SERVER_ERROR) {
      this.logger.error(`[${errorCode}] ${message}`, exception instanceof Error ? exception.stack : undefined);
    }

    response.status(status).json(payload);
  }

  private normalizeException(exception: unknown) {
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const response = exception.getResponse();
      const fallbackMessage = exception.message || 'Request failed.';
      const message = this.extractMessage(response, fallbackMessage);
      const errorCode = this.extractErrorCode(response) ?? this.statusToErrorCode(status);

      return { status, message, errorCode };
    }

    return {
      status: HttpStatus.INTERNAL_SERVER_ERROR,
      message: 'Internal server error.',
      errorCode: 'INTERNAL_ERROR'
    };
  }

  private extractMessage(response: string | object, fallback: string): string {
    if (typeof response === 'string') {
      return response;
    }

    if (response && typeof response === 'object') {
      const message = (response as { message?: string | string[] }).message;

      if (Array.isArray(message)) {
        return message[0] ?? fallback;
      }

      if (typeof message === 'string') {
        return message;
      }
    }

    return fallback;
  }

  private extractErrorCode(response: string | object): string | null {
    if (!response || typeof response !== 'object') {
      return null;
    }

    return (response as { errorCode?: string }).errorCode ?? null;
  }

  private statusToErrorCode(status: number): string {
    switch (status) {
      case HttpStatus.BAD_REQUEST:
        return 'BAD_REQUEST';
      case HttpStatus.UNAUTHORIZED:
        return 'UNAUTHORIZED';
      case HttpStatus.FORBIDDEN:
        return 'FORBIDDEN';
      case HttpStatus.NOT_FOUND:
        return 'NOT_FOUND';
      case HttpStatus.CONFLICT:
        return 'CONFLICT';
      case HttpStatus.TOO_MANY_REQUESTS:
        return 'TOO_MANY_REQUESTS';
      default:
        return 'INTERNAL_ERROR';
    }
  }
}
