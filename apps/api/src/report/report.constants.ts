export const REPORT_QUEUE = 'report-jobs';
export const REPORT_GENERATE_JOB = 'generate-report';

const DEFAULT_REPORT_EXPIRY_INTERVAL_MS = 15 * 60 * 1000;

function parseReportExpiryInterval(): number {
  const rawValue = process.env.REPORT_EXPIRY_INTERVAL_MS;

  if (!rawValue) {
    return DEFAULT_REPORT_EXPIRY_INTERVAL_MS;
  }

  const parsedValue = Number.parseInt(rawValue, 10);

  if (!Number.isFinite(parsedValue) || parsedValue <= 0) {
    return DEFAULT_REPORT_EXPIRY_INTERVAL_MS;
  }

  return parsedValue;
}

export const REPORT_EXPIRY_INTERVAL_MS = parseReportExpiryInterval();
