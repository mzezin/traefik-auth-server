import Fastify, { FastifyInstance, FastifyRequest, FastifyReply, FastifyBaseLogger } from 'fastify';
import basicAuth from '@fastify/basic-auth';
import { join } from 'path';
import { authenticate } from 'htpasswd-js';
import { loadHtpasswd, loadWhitelist, loadErrorPage, parsePort, parseHost, recordFailedAttempt, resetAttempts, isIPInRange } from './utils';

// Interface for user object attached to request
interface User {
  username: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    user?: User;
  }
}

// Directory paths
const configDir = join(__dirname, '../config');
const publicDir = join(__dirname, '../pages');

// File paths
const htpasswdPath = join(configDir, '.htpasswd');
const whitelistPath = join(configDir, 'whitelist.json');
const errorPages = {
  '401': join(publicDir, '401.html'),
  '403': join(publicDir, '403.html'),
  '404': join(publicDir, '404.html'),
  '429': join(publicDir, '429.html'),
};

// Cached data
let cachedHtpasswd: string | null | undefined = undefined;
let cachedWhitelist: string[] | undefined = undefined;
let cachedErrorPages: { [key: string]: string } | undefined = undefined;
let rateLimitMap = new Map<string, { attempts: number; blockedUntil: number }>();

// Environment variables with defaults
const HOST = process.env.HOST || '0.0.0.0';
const AUTH_PORT = process.env.AUTH_PORT || '3000';
const WHITELIST_PORT = process.env.WHITELIST_PORT || '3001';
const NOT_FOUND_PORT = process.env.NOT_FOUND_PORT || '3002';

// Extracts client IP from request headers
const getClientIP = (request: FastifyRequest): string => {
  const forwardedFor = request.headers['x-forwarded-for'];
  let clientIP = request.ip;
  if (forwardedFor) {
    const ips = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor;
    clientIP = ips.split(',')[0].trim();
  }
  return clientIP;
};

// Validates basic auth credentials and IP
const validateBasicAuth = async (
  username: string,
  password: string,
  req: FastifyRequest,
  reply: FastifyReply,
  logger: FastifyBaseLogger
): Promise<void | Error> => {
  if (cachedHtpasswd === undefined) {
    return new Error('Server not initialized');
  }
  if (!cachedHtpasswd) {
    recordFailedAttempt(getClientIP(req), rateLimitMap, logger);
    return new Error('Authentication failed');
  }
  try {
    const isAuthenticated = await authenticate({
      data: cachedHtpasswd,
      username,
      password,
    });
    const clientIP = getClientIP(req);
    if (!isAuthenticated) {
      recordFailedAttempt(clientIP, rateLimitMap, logger);
      return new Error('Authentication failed');
    }
    if (!cachedWhitelist || !isIPInRange(clientIP, cachedWhitelist)) {
      return new Error('IP not in whitelist');
    }
    resetAttempts(clientIP, rateLimitMap);
    logger.info({ msg: `User ${username} authenticated successfully from IP ${clientIP}`, username, clientIP });
    req.user = { username };
    return;
  } catch (err) {
    return err instanceof Error ? err : new Error('Authentication failed');
  }
};

// Sets up authentication server with basic auth
export const setupAuthServer = async (logger: FastifyBaseLogger): Promise<FastifyInstance> => {
  const server = Fastify({ logger: true });
  server.addHook('onRequest', async (request, reply) => {
    if (!cachedErrorPages) {
      logger.error({ msg: 'Server not initialized: cachedErrorPages is undefined' });
      reply.code(500).send('Server not initialized');
      return;
    }
    const clientIp = getClientIP(request);
    const now = Date.now();
    let record = rateLimitMap.get(clientIp);
    if (!record) {
      record = { attempts: 0, blockedUntil: 0 };
      rateLimitMap.set(clientIp, record);
    }
    logger.debug({ msg: `Checking rate limit for IP ${clientIp}, blocked until ${record.blockedUntil || 0}`, clientIp, blockedUntil: record.blockedUntil });
    if (record.blockedUntil > now) {
      logger.warn({ msg: `Blocked request from ${clientIp} until ${record.blockedUntil}`, clientIp, blockedUntil: record.blockedUntil });
      reply.code(429).type('text/html').send(cachedErrorPages['429']);
      return;
    }
  });
  await server.register(basicAuth, {
    validate: (username, password, req, reply) => validateBasicAuth(username, password, req, reply, server.log),
    authenticate: true,
  });
  server.setErrorHandler((error, request, reply) => {
    if (!cachedErrorPages) {
      logger.error({ msg: 'Server not initialized: cachedErrorPages is undefined' });
      reply.code(500).send('Server not initialized');
      return;
    }
    if (error.message === 'Authentication failed' || error.code === 'FST_BASIC_AUTH_MISSING_OR_BAD_AUTHORIZATION_HEADER') {
      reply
        .code(401)
        .header('WWW-Authenticate', 'Basic realm="Restricted Area"')
        .type('text/html')
        .send(cachedErrorPages['401']);
    } else if (error.message === 'IP not in whitelist') {
      reply
        .code(403)
        .type('text/html')
        .send(cachedErrorPages['403']);
    } else {
      reply.send(error);
    }
  });
  server.after(() => {
    server.route({
      method: 'GET',
      url: '/',
      onRequest: server.basicAuth,
      handler: async (request, reply) => {
        if (!request.user) {
          logger.error({ msg: 'User not authenticated' });
          reply.code(500).send('User not authenticated');
          return;
        }
        reply.header('X-Forwarded-User', request.user.username);
        return '';
      },
    });
  });
  return server;
};

// Sets up server restricting access by whitelist
export const setupWhitelistOnlyServer = async (logger: FastifyBaseLogger): Promise<FastifyInstance> => {
  const server = Fastify({ logger: true });
  server.addHook('preHandler', (request, reply, done) => {
    if (!cachedWhitelist || !cachedErrorPages) {
      logger.error({ msg: 'Server not initialized: cachedWhitelist or cachedErrorPages is undefined' });
      reply.code(500).send('Server not initialized');
      return;
    }
    const clientIP = getClientIP(request);
    if (!isIPInRange(clientIP, cachedWhitelist)) {
      reply
        .code(403)
        .type('text/html')
        .send(cachedErrorPages['403']);
      return;
    }
    done();
  });
  server.get('/', async (request, reply) => {
    reply.header('X-Whitelist-Allowed', 'true');
    return '';
  });
  return server;
};

// Sets up server returning 404 for all requests
export const setupNotFoundServer = async (logger: FastifyBaseLogger): Promise<FastifyInstance> => {
  const server = Fastify({ logger: true });
  server.setNotFoundHandler((request, reply) => {
    if (!cachedErrorPages) {
      logger.error({ msg: 'Server not initialized: cachedErrorPages is undefined' });
      reply.code(500).send('Server not initialized');
      return;
    }
    reply
      .code(404)
      .type('text/html')
      .send(cachedErrorPages['404']);
  });
  return server;
};

// Starts all servers on configured ports
export const start = async () => {
  const server = Fastify({ logger: true });
  // Validate environment variables
  const host = parseHost(HOST, '0.0.0.0', server.log);
  const authPort = parsePort(AUTH_PORT, 3000, false, server.log);
  const whitelistPort = parsePort(WHITELIST_PORT, 3001, false, server.log);
  const notFoundPort = parsePort(NOT_FOUND_PORT, 3002, false, server.log);

  server.log.info({ msg: `Starting servers on ports ${authPort}, ${whitelistPort}, ${notFoundPort}`, ports: { authPort, whitelistPort, notFoundPort } });
  try {
    // Initialize rate limit map (redundant but kept for consistency)
    rateLimitMap = new Map<string, { attempts: number; blockedUntil: number }>();

    // Clean up rate limit map hourly
    setInterval(() => {
      const now = Date.now();
      for (const [ip, record] of rateLimitMap.entries()) {
        if (record.blockedUntil < now) rateLimitMap.delete(ip);
      }
    }, 60 * 60 * 1000); // Every hour

    // Load and cache configuration files
    cachedHtpasswd = loadHtpasswd(htpasswdPath, server.log);
    cachedWhitelist = loadWhitelist(whitelistPath, server.log);
    cachedErrorPages = {
      '401': loadErrorPage(errorPages['401'], server.log),
      '403': loadErrorPage(errorPages['403'], server.log),
      '404': loadErrorPage(errorPages['404'], server.log),
      '429': loadErrorPage(errorPages['429'], server.log),
    };

    const authServer = await setupAuthServer(server.log);
    const notFoundServer = await setupNotFoundServer(server.log);
    const whitelistOnlyServer = await setupWhitelistOnlyServer(server.log);
    await Promise.all([
      authServer.listen({ port: authPort, host }),
      whitelistOnlyServer.listen({ port: whitelistPort, host }),
      notFoundServer.listen({ port: notFoundPort, host }),
    ]);
    server.log.info({ msg: 'Servers started successfully' });
  } catch (err) {
    server.log.error({ msg: 'Server startup failed', error: err instanceof Error ? err.message : String(err) });
    throw err;
  }
};

if (require.main === module) {
  start();
}