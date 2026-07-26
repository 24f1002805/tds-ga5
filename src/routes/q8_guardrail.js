// src/routes/q8_guardrail.js
import fs from 'node:fs/promises';
import path from 'node:path';

const SANDBOX_ROOT = '/srv/agent-redteam/sandbox-44ebd10bfe';
const ALLOWED_HOSTS = new Set(['example.com', 'www.iana.org']);

/**
 * Checks if a target path stays strictly inside the sandbox directory.
 */
function isPathSafe(requestedPath) {
  if (typeof requestedPath !== 'string' || !requestedPath.trim()) {
    return false;
  }

  // Resolve path relative to SANDBOX_ROOT if relative, or resolve absolute path
  const resolvedPath = path.isAbsolute(requestedPath)
    ? path.resolve(requestedPath)
    : path.resolve(SANDBOX_ROOT, requestedPath);

  // Path MUST start with SANDBOX_ROOT (with trailing separator check to avoid prefix attacks)
  const normalizedSandbox = path.resolve(SANDBOX_ROOT);
  const relative = path.relative(normalizedSandbox, resolvedPath);

  // Safe if relative does not start with '..' and is not absolute
  const isSafe = !relative.startsWith('..') && !path.isAbsolute(relative);
  return isSafe;
}

/**
 * Checks if a target URL is strictly allowed.
 */
function isUrlSafe(urlString) {
  if (typeof urlString !== 'string' || !urlString.trim()) {
    return false;
  }

  try {
    const parsed = new URL(urlString);

    // Only HTTP/HTTPS allowed
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }

    // Disallow userinfo (e.g., http://user:pass@example.com)
    if (parsed.username || parsed.password) {
      return false;
    }

    const hostname = parsed.hostname.toLowerCase();

    // Check exact allowed hosts
    if (!ALLOWED_HOSTS.has(hostname)) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

export async function q8GuardrailRoutes(fastify) {
  fastify.post('/v1/guardrail', async (req, reply) => {
    const body = req.body || {};
    const tool = body.tool;
    const args = body.arguments || {};

    const allow = async (result) => {
      return reply.type('application/json').send({
        action: 'allow',
        reason: 'Operation allowed within sandbox security constraints.',
        result
      });
    };

    const block = (reason) => {
      return reply.type('application/json').send({
        action: 'block',
        reason
      });
    };

    // ----------------------------------------------------
    // 1. TOOL: read_file
    // ----------------------------------------------------
    if (tool === 'read_file') {
      const filePath = args.path;

      if (!filePath || typeof filePath !== 'string') {
        return block('Invalid or missing path argument.');
      }

      if (!isPathSafe(filePath)) {
        return block('Access denied: Requested path is outside the allowed sandbox directory.');
      }

      // Resolve full path to actually read the file
      const targetPath = path.isAbsolute(filePath)
        ? path.resolve(filePath)
        : path.resolve(SANDBOX_ROOT, filePath);

      try {
        const content = await fs.readFile(targetPath, 'utf8');

        // Double check canary safety before sending
        if (content.includes('AGENT_GUARDRAIL_CANARY')) {
          return block('Access denied: Canary content detected.');
        }

        return allow({ content });
      } catch (err) {
        if (err.code === 'ENOENT') {
          return block('File not found.');
        }
        return block(`Failed to read file: ${err.message}`);
      }
    }

    // ----------------------------------------------------
    // 2. TOOL: fetch_url
    // ----------------------------------------------------
    if (tool === 'fetch_url') {
      const url = args.url;

      if (!url || typeof url !== 'string') {
        return block('Invalid or missing url argument.');
      }

      if (!isUrlSafe(url)) {
        return block('Access denied: Requested host/protocol is not permitted.');
      }

      try {
        const res = await fetch(url, { redirect: 'error', timeout: 5000 });
        if (!res.ok) {
          return block(`HTTP fetch failed with status ${res.status}`);
        }
        const text = await res.text();
        return allow({ content: text });
      } catch (err) {
        return block(`Failed to fetch URL: ${err.message}`);
      }
    }

    return block(`Unknown tool: ${tool}`);
  });

  // Alias endpoints for flexibility
  fastify.post('/guardrail', async (req, reply) => {
    return fastify.inject({
      method: 'POST',
      url: '/v1/guardrail',
      payload: req.body,
      headers: req.headers
    }).then(res => reply.status(res.statusCode).send(res.json()));
  });
}
