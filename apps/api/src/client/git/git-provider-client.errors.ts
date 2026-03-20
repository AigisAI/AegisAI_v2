import type { Provider } from '@aegisai/shared';

export class GitProviderClientError extends Error {
  constructor(
    message: string,
    public readonly provider: Provider,
    public readonly statusCode?: number
  ) {
    super(message);
    this.name = new.target.name;
  }
}

export class GitProviderUnauthorizedError extends GitProviderClientError {}

export class GitProviderNotFoundError extends GitProviderClientError {}

export class GitProviderRateLimitError extends GitProviderClientError {
  constructor(
    message: string,
    provider: Provider,
    statusCode?: number,
    public readonly resetAtEpochSeconds?: number
  ) {
    super(message, provider, statusCode);
    this.name = new.target.name;
  }
}

export class GitProviderUnavailableError extends GitProviderClientError {}
