export type Provider = 'github' | 'gitlab';

export interface SuccessResponse<T> {
  success: true;
  data: T;
  message: string | null;
  timestamp: string;
}

export interface ErrorResponse {
  success: false;
  data: null;
  message: string;
  errorCode: string;
  timestamp: string;
}

export type ApiResponse<T> = SuccessResponse<T> | ErrorResponse;

export interface PageResponse<T> {
  items: T[];
  totalCount: number;
  page: number;
  totalPages: number;
}

export interface CursorPageResponse<T> {
  items: T[];
  page: number;
  size: number;
  hasNextPage: boolean;
  nextPage: number | null;
}

export interface PageQuery {
  page?: number;
  size?: number;
}
