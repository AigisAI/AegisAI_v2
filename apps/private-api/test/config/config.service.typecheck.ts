import { ConfigService } from '../../src/config/config.service';

declare const config: ConfigService;

const port: number = config.get('PORT');
const reportExpiryHours: number = config.get('REPORT_EXPIRY_HOURS');
const databaseUrl: string = config.get('DATABASE_URL');
const optionalPort: number | undefined = config.getOptional('PORT');
const optionalCookieDomain: string | undefined = config.getOptional('COOKIE_DOMAIN');

void port;
void reportExpiryHours;
void databaseUrl;
void optionalPort;
void optionalCookieDomain;
