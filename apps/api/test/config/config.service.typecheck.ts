import { ConfigService } from '../../src/config/config.service';

declare const config: ConfigService;

const port: number = config.get('PORT');
const reportExpiryHours: number = config.get('REPORT_EXPIRY_HOURS');
const evidenceStoragePath: string = config.get('EVIDENCE_STORAGE_PATH');
const evidenceExpiryIntervalMs: number = config.get('EVIDENCE_EXPIRY_INTERVAL_MS');
const aiAdvisoryTimeoutMs: number = config.get('AI_ADVISORY_TIMEOUT_MS');
const databaseUrl: string = config.get('DATABASE_URL');
const optionalPort: number | undefined = config.getOptional('PORT');
const optionalCookieDomain: string | undefined = config.getOptional('COOKIE_DOMAIN');
const optionalTeamsWebhookUrl: string | undefined = config.getOptional('TEAMS_WEBHOOK_URL');

void port;
void reportExpiryHours;
void evidenceStoragePath;
void evidenceExpiryIntervalMs;
void aiAdvisoryTimeoutMs;
void databaseUrl;
void optionalPort;
void optionalCookieDomain;
void optionalTeamsWebhookUrl;
