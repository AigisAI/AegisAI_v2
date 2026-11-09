import { resolve } from 'node:path';

const apiRoot = resolve(__dirname, '..', '..');
const workspaceRoot = resolve(apiRoot, '..', '..');

export const ENV_FILE_PATHS = [resolve(workspaceRoot, '.env'), resolve(apiRoot, '.env')];
