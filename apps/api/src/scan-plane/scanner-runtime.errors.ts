import type { SastFailureClass } from '@aegisai/shared';
import { HttpException, HttpStatus } from '@nestjs/common';

export class SastScannerRuntimeError extends HttpException {
  constructor(
    message: string,
    readonly failureClass: SastFailureClass,
    readonly reasonCode: string,
    readonly retryAllowed: boolean
  ) {
    super(
      {
        message,
        errorCode: reasonCode,
        failureClass,
        retryAllowed
      },
      statusForFailureClass(failureClass)
    );
    this.name = 'SastScannerRuntimeError';
  }
}

export function securityViolation(
  reasonCode: string,
  message: string
): SastScannerRuntimeError {
  return new SastScannerRuntimeError(
    message,
    'SECURITY_VIOLATION',
    reasonCode,
    false
  );
}

export function scannerDefect(
  reasonCode: string,
  message: string
): SastScannerRuntimeError {
  return new SastScannerRuntimeError(
    message,
    'SCANNER_DEFECT',
    reasonCode,
    false
  );
}

export function retryableInfrastructureFailure(
  reasonCode: string,
  message: string
): SastScannerRuntimeError {
  return new SastScannerRuntimeError(
    message,
    'RETRYABLE_INFRASTRUCTURE',
    reasonCode,
    true
  );
}

function statusForFailureClass(failureClass: SastFailureClass): HttpStatus {
  if (failureClass === 'SECURITY_VIOLATION') {
    return HttpStatus.FORBIDDEN;
  }
  if (
    failureClass === 'RETRYABLE_INFRASTRUCTURE' ||
    failureClass === 'CAPACITY_REJECTED'
  ) {
    return HttpStatus.SERVICE_UNAVAILABLE;
  }
  if (failureClass === 'SCANNER_DEFECT') {
    return HttpStatus.BAD_GATEWAY;
  }
  return HttpStatus.UNPROCESSABLE_ENTITY;
}
