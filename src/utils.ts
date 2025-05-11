import { readFileSync } from 'fs';
import { Netmask } from 'netmask';
import { FastifyBaseLogger } from 'fastify';

// Generates default HTML error page for given error code
export const generateDefaultErrorPage = (errorCode: string): string => {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${errorCode}</title>
      <style>
        body { display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; font-family: Arial, sans-serif; background: #f0f0f0; }
        h1 { font-size: 72px; color: #333; }
      </style>
    </head>
    <body>
      <h1>${errorCode}</h1>
    </body>
    </html>
  `;
};

// Reads file safely, throwing error on failure
export const readFileSafely = (path: string): string => {
  try {
    return readFileSync(path, 'utf8');
  } catch (err: any) {
    throw new Error(`Failed to load file ${path}: ${err}`);
  }
};

// Loads error page or generates default if missing
export const loadErrorPage = (path: string, logger: FastifyBaseLogger): string => {
  const errorCode = path.match(/(\d{3})\.html$/)?.[1] || 'Unknown';
  try {
    const content = readFileSafely(path);
    logger.info({ msg: `Loaded error page ${errorCode} from ${path}` });
    return content;
  } catch (err: any) {
    if (err.message.includes('ENOENT') && ['401.html', '403.html', '404.html', '429.html'].some(file => path.endsWith(file))) {
      logger.warn({ msg: `Failed to load error page ${errorCode} from ${path}: File not found, using default` });
      return generateDefaultErrorPage(errorCode);
    }
    logger.error({ msg: `Failed to load error page ${errorCode} from ${path}: ${err.message}`});
    throw err;
  }
};

// Loads .htpasswd file or returns null if missing
export const loadHtpasswd = (path: string, logger: FastifyBaseLogger): string | null => {
  try {
    const content = readFileSafely(path);
    logger.info({ msg: `Loaded .htpasswd from ${path}` });
    return content;
  } catch (err: any) {
    if (err.message.includes('ENOENT')) {
      logger.warn({ msg: `Failed to load .htpasswd from ${path}: File not found, rejecting all authentication attempts`});
      return null;
    }
    logger.error({ msg: `Failed to load .htpasswd from ${path}: ${err.message}`});
    throw err;
  }
};

// Loads whitelist from JSON file with fallback to 192.168.1.1/24
export const loadWhitelist = (path: string, logger: FastifyBaseLogger): string[] => {
  try {
    const data = readFileSafely(path);
    const json = JSON.parse(data);
    if (!Array.isArray(json)) {
      throw new Error('Whitelist is not an array');
    }
    const validEntries = json.filter((entry) => {
      try {
        new Netmask(entry);
        return true;
      } catch {
        logger.warn({ msg: `Invalid CIDR or IP in whitelist: ${entry}` });
        return false;
      }
    });
    logger.info({ msg: `Loaded whitelist from ${path} with ${validEntries.length} valid entries`, details: { validEntries } });
    return validEntries.length > 0 ? validEntries : ['192.168.1.1/24'];
  } catch (err: any) {
    logger.warn({ msg: `Failed to load whitelist from ${path}, falling back to 192.168.1.1/24` });
    try {
      new Netmask('192.168.1.1/24'); // Validate fallback
      return ['192.168.1.1/24'];
    } catch {
      logger.error({ msg: `Failed to load whitelist from ${path}: Invalid fallback CIDR 192.168.1.1/24` });
      throw new Error('Invalid fallback CIDR');
    }
  }
};

// Parses port from environment variable with validation
export const parsePort = (
  envVar: string | undefined,
  defaultPort: number,
  allowPrivileged = false,
  logger: FastifyBaseLogger
): number => {
  const port = Number(envVar);
  const minPort = allowPrivileged ? 1 : 1024;
  if (!Number.isInteger(port) || port < minPort || port > 65535) {
    logger.warn({ msg: `Invalid port value "${envVar}", using default ${defaultPort}`, envVar, defaultPort });
    return defaultPort;
  }
  return port;
};

// Parses host from environment variable with validation
export const parseHost = (
  envVar: string | undefined,
  defaultHost: string,
  logger: FastifyBaseLogger
): string => {
  if (!envVar || !/^(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0)$/.test(envVar)) {
    logger.warn({ msg: `Invalid host value "${envVar}", using default ${defaultHost}`, envVar, defaultHost });
    return defaultHost;
  }
  return envVar;
};

// Records a failed authentication attempt for an IP
export const recordFailedAttempt = (
  ip: string,
  rateLimitMap: Map<string, { attempts: number; blockedUntil: number }>,
  logger: FastifyBaseLogger
) => {
  const now = Date.now();
  let record = rateLimitMap.get(ip);
  if (!record) {
    record = { attempts: 0, blockedUntil: 0 };
    rateLimitMap.set(ip, record);
  }
  record.attempts += 1;
  if (record.attempts >= 5) {
    record.blockedUntil = now + 60 * 60 * 1000; // 1 hour
    logger.warn({ msg: `IP ${ip} blocked for 1 hour due to too many failed attempts`, ip, blockedUntil: record.blockedUntil });
  }
  rateLimitMap.set(ip, record);
};

// Resets failed attempt counter for an IP
export const resetAttempts = (ip: string, rateLimitMap: Map<string, { attempts: number; blockedUntil: number }>) => {
  rateLimitMap.set(ip, { attempts: 0, blockedUntil: 0 });
};

// Checks if IP is in whitelist CIDR range
export const isIPInRange = (ip: string, whitelist: string[]): boolean => {
  try {
    return whitelist.some((cidr) => {
      const block = new Netmask(cidr);
      return block.contains(ip);
    });
  } catch (err) {
    return false;
  }
};