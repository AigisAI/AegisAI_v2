import { GetSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";

const AUTH_KEYS=new Set(['DATABASE_URL','REDIS_URL','SESSION_SECRET','CSRF_SECRET','GITHUB_CLIENT_ID','GITHUB_CLIENT_SECRET',
  'GITHUB_LOGIN_KIND','ALLOWED_GITHUB_USER_IDS','GITLAB_CLIENT_ID','GITLAB_CLIENT_SECRET','APP_URL','FRONTEND_URL',
  'SESSION_COOKIE_NAME','CSRF_COOKIE_NAME','COOKIE_DOMAIN','COOKIE_SECURE','SESSION_TTL_SECONDS','THROTTLE_TTL_MS',
  'THROTTLE_LIMIT','TOKEN_ENCRYPTION_KEY','INTERNAL_API_SECRET','REPORT_STORAGE_PATH','REPORT_EXPIRY_HOURS','USE_INTERNAL_AI','ANALYSIS_CLIENT_MODE']);
const SCM_KEYS=new Set(['DATABASE_URL','GITHUB_APP_ID','GITHUB_APP_SLUG','GITHUB_APP_PRIVATE_KEY_PEM','ALLOWED_GITHUB_USER_IDS']);

/** Startup only; decrypted values remain in process memory, never Docker env metadata/files. */
export async function loadRuntimeSecrets(scope:"api"|"broker"|"data"):Promise<void> {
  if(process.env.NODE_ENV!=="production") return;
  const region=process.env.AWS_REGION;
  const scm=process.env.AWS_SCM_SECRET_ARN;
  const auth=process.env.AWS_AUTH_SECRET_ARN;
  if(region!=="ap-northeast-2" || ((scope==="api"||scope==="broker")&&!scm) || ((scope==="api"||scope==="data")&&!auth)) throw new Error("RUNTIME_SECRET_REFERENCES_REQUIRED");
  const client=new SecretsManagerClient({region,maxAttempts:2});
  try {
    for(const [id,allowed] of (scope==="api"?[[auth!,AUTH_KEYS],[scm!,SCM_KEYS]]:scope==="data"?[[auth!,AUTH_KEYS]]:[[scm!,SCM_KEYS]]) as Array<[string,Set<string>]>) {
      if(!/^arn:aws:secretsmanager:ap-northeast-2:024139495514:secret:aegisai\/private-runtime\/(auth|scm)-[A-Za-z0-9]+$/.test(id)) throw new Error();
      const reply=await client.send(new GetSecretValueCommand({SecretId:id}),{abortSignal:AbortSignal.timeout(10_000)});
      if(!reply.SecretString || Buffer.byteLength(reply.SecretString)>65536) throw new Error();
      const data=JSON.parse(reply.SecretString);
      if(data.version!==1 || !data.values || typeof data.values!=="object" || Array.isArray(data.values)) throw new Error();
      for(const [key,value] of Object.entries(data.values)) {
        if(!allowed.has(key) || typeof value!=="string" || value.includes("\0")) throw new Error();
        if(scope==="data"&&key!=="DATABASE_URL") continue;
        if((key==="DATABASE_URL"||key==="ALLOWED_GITHUB_USER_IDS"||key==="GITHUB_LOGIN_KIND") && process.env[key] && process.env[key]!==value) throw new Error();
        process.env[key]=value;
      }
    }
    if(scope!=="data"&&!process.env.GITHUB_APP_PRIVATE_KEY_PEM?.includes("PRIVATE KEY")) throw new Error();
    // A production process must not fall back to a durable signing-key copy.
    delete process.env.GITHUB_APP_PRIVATE_KEY_PATH;
  } catch {throw new Error("RUNTIME_SECRETS_UNAVAILABLE");}
  finally {client.destroy();}
}
