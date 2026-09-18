/**
 * @module main/integrations/integration-credentials
 *
 * Secret-safe credential resolution for adapters.
 *
 * Per CYBER_BUILD_RULES rule 20 (never expose secrets in logs, prompts or UI)
 * and rule 26 (vendor-specific integrations belong behind adapters), all
 * credentials are resolved through this module. Adapters never see raw
 * `process.env` and never log the credential material. Errors are redacted
 * before being surfaced.
 *
 * Resolution order (first non-empty wins):
 *   1. Explicit override map (e.g. test fixtures)
 *   2. process.env (key matched against env var name)
 *   3. configStore provider (typed credential map)
 *
 * No defaults are ever baked into the codebase; missing credentials surface
 * as `IntegrationUnavailableError` with a stable reason code.
 */

export type CredentialSource = 'override' | 'env' | 'config';

export interface CredentialResolverOptions {
  env?: NodeJS.ProcessEnv;
  configStore?: CredentialConfigProvider;
  overrides?: Record<string, string>;
}

export interface CredentialConfigProvider {
  getCredential(domain: string, vendor: string, key: string): string | undefined;
}

export interface ResolvedCredential {
  value: string;
  source: CredentialSource;
}

export const REDACTED_VALUE = '[redacted]';

function lookupEnv(env: NodeJS.ProcessEnv | undefined, key: string): string | undefined {
  if (!env) return undefined;
  const value = env[key];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

export class IntegrationCredentialResolver {
  private readonly env: NodeJS.ProcessEnv | undefined;
  private readonly configStore: CredentialConfigProvider | undefined;
  private readonly overrides: Record<string, string>;

  constructor(options: CredentialResolverOptions = {}) {
    this.env = options.env;
    this.configStore = options.configStore;
    this.overrides = { ...(options.overrides || {}) };
  }

  withOverrides(overrides: Record<string, string>): IntegrationCredentialResolver {
    return new IntegrationCredentialResolver({
      env: this.env,
      configStore: this.configStore,
      overrides: { ...this.overrides, ...overrides },
    });
  }

  resolve(domain: string, vendor: string, envVarName: string, configKey?: string): ResolvedCredential | null {
    const overrideKey = `${domain}.${vendor}.${envVarName}`;
    const override = this.overrides[overrideKey];
    if (override && override.length > 0) {
      return { value: override, source: 'override' };
    }
    const fromEnv = lookupEnv(this.env, envVarName);
    if (fromEnv) {
      return { value: fromEnv, source: 'env' };
    }
    if (this.configStore && configKey) {
      const fromConfig = this.configStore.getCredential(domain, vendor, configKey);
      if (fromConfig && fromConfig.length > 0) {
        return { value: fromConfig, source: 'config' };
      }
    }
    return null;
  }

  resolveMany(domain: string, vendor: string, requirements: Array<{ envVar: string; configKey?: string }>): Record<string, ResolvedCredential> | null {
    const resolved: Record<string, ResolvedCredential> = {};
    for (const req of requirements) {
      const credential = this.resolve(domain, vendor, req.envVar, req.configKey);
      if (!credential) return null;
      resolved[req.envVar] = credential;
    }
    return resolved;
  }

  missingRequirements(domain: string, vendor: string, requirements: Array<{ envVar: string; configKey?: string }>): string[] {
    return requirements
      .filter((req) => !this.resolve(domain, vendor, req.envVar, req.configKey))
      .map((req) => req.envVar);
  }
}

const SENSITIVE_OBJECT_KEY_RE = /secret|token|password|apikey|api[_-]?key|authorization|auth|credential|payload|body|data|value|cookie|jwt|signature|private|pem/i;

function redactCredentialString(raw: string): string {
  let next = raw;

  next = next.replace(
    /\b(sk-[A-Za-z0-9._-]{8,}|pk-[A-Za-z0-9._-]{8,}|rk_[A-Za-z0-9._-]{8,}|ghp_[A-Za-z0-9_]{8,}|gho_[A-Za-z0-9_]{8,}|ghu_[A-Za-z0-9_]{8,}|ghs_[A-Za-z0-9_]{8,}|xox[baprs]-[A-Za-z0-9-]{8,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{20,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b)/g,
    REDACTED_VALUE
  );

  next = next.replace(/\b[A-Za-z0-9+/]{8,}={0,2}\b/g, (match) => {
    if (match.length < 8) return match;
    if (match.length >= 32) return REDACTED_VALUE;
    const unique = new Set(match.toLowerCase());
    const alphaCount = (match.match(/[A-Za-z]/g) || []).length;
    const digitCount = (match.match(/[0-9]/g) || []).length;
    const plusSlash = (match.match(/[+/]/g) || []).length;
    const base64Ratio = (alphaCount + digitCount + plusSlash) / match.length;
    if (unique.size >= 6 && base64Ratio >= 0.9) return REDACTED_VALUE;
    return match;
  });

  next = next.replace(
    /\b(Bearer|Basic|Token|ApiKey|BearerToken)\s+[A-Za-z0-9._\-+/%=]+/gi,
    (_match, scheme) => `${scheme} ${REDACTED_VALUE}`
  );

  next = next.replace(/api[_-]?key\s*[=:]\s*[^\s,;]+/gi, `api_key=${REDACTED_VALUE}`);

  next = next.replace(/(client_secret|access_token|refresh_token|id_token|session_key|private_key)\s*[=:]\s*[^\s,;&"'`]+/gi, (_, k) => `${k}=${REDACTED_VALUE}`);

  return next;
}

export function redactCredential(error: unknown): unknown {
  if (!error) return error;
  if (typeof error === 'string') {
    return redactCredentialString(error);
  }
  if (error instanceof Error) {
    const redacted = new Error(redactCredential(error.message) as string);
    redacted.name = error.name;
    redacted.stack = error.stack ? (redactCredential(error.stack) as string) : undefined;
    return redacted;
  }
  if (typeof error === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(error as Record<string, unknown>)) {
      if (SENSITIVE_OBJECT_KEY_RE.test(key)) {
        out[key] = REDACTED_VALUE;
      } else {
        out[key] = redactCredential(value);
      }
    }
    return out;
  }
  return error;
}
