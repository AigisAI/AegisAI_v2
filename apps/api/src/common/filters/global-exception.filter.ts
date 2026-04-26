import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Injectable,
  Logger
} from "@nestjs/common";

interface ErrorResponseBody {
  success: false;
  data: null;
  message: string;
  errorCode: string;
  timestamp: string;
}

@Catch()
@Injectable()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GlobalExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const request = host.switchToHttp().getRequest<{
      method: string;
      originalUrl?: string;
      url?: string;
    }>();
    const response = host.switchToHttp().getResponse<{
      status(code: number): { json(body: ErrorResponseBody): void };
    }>();
    const normalized = this.normalizeException(exception);
    const timestamp = new Date().toISOString();
    const payload: ErrorResponseBody = {
      success: false,
      data: null,
      message: normalized.message,
      errorCode: normalized.errorCode,
      timestamp
    };

    if (normalized.status >= HttpStatus.INTERNAL_SERVER_ERROR) {
      this.logger.error(
        JSON.stringify({
          marker: "runtime_error",
          status: normalized.status,
          errorCode: normalized.errorCode,
          method: request.method,
          path: request.originalUrl || request.url || "/",
          message: normalized.message,
          timestamp
        }),
        exception instanceof Error ? exception.stack : undefined
      );
    }

    response.status(normalized.status).json(payload);
  }

  private normalizeException(exception: unknown) {
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const body = exception.getResponse();
      const fallbackMessage = exception.message || "Request failed.";
      const message = this.extractMessage(body, fallbackMessage);
      const errorCode = this.extractErrorCode(body) ?? this.statusToErrorCode(status);

      return { status, message, errorCode };
    }

    return {
      status: HttpStatus.INTERNAL_SERVER_ERROR,
      message: "Internal server error.",
      errorCode: "INTERNAL_ERROR"
    };
  }

  private extractMessage(body: string | object, fallback: string): string {
    if (typeof body === "string") {
      return body;
    }

    if (body && typeof body === "object") {
      const { message } = body as { message?: string | string[] };

      if (Array.isArray(message)) {
        return message[0] ?? fallback;
      }

      if (typeof message === "string") {
        return message;
      }
    }

    return fallback;
  }

  private extractErrorCode(body: string | object): string | null {
    if (!body || typeof body !== "object") {
      return null;
    }

    return (body as { errorCode?: string }).errorCode ?? null;
  }

  private statusToErrorCode(status: number): string {
    switch (status) {
      case HttpStatus.BAD_REQUEST:
        return "BAD_REQUEST";
      case HttpStatus.UNAUTHORIZED:
        return "UNAUTHORIZED";
      case HttpStatus.FORBIDDEN:
        return "FORBIDDEN";
      case HttpStatus.NOT_FOUND:
        return "NOT_FOUND";
      case HttpStatus.CONFLICT:
        return "CONFLICT";
      case HttpStatus.TOO_MANY_REQUESTS:
        return "TOO_MANY_REQUESTS";
      default:
        return "INTERNAL_ERROR";
    }
  }
}
