// src/routes/q8_guardrail.js
import fs from 'node:fs/promises';
import path from 'node:path';

const SANDBOX_ROOT = '/srv/agent-redteam/sandbox-44ebd10bfe';
const ALLOWED_HOSTS = new Set(['example.com', 'www.iana.org']);

/**
 * Validates if the path remains inside SANDBOX_ROOT after resolving.
 */
function isPathSafe(requestedPath) {
  if (typeof requestedPath !== 'string' || !requestedPath.trim()) {
    return false;
  }

  // Always resolve relative paths against SANDBOX_ROOT
  const resolvedPath = path.isAbsolute(requestedPath)
    ? path.resolve(requestedPath)
    : path.resolve(SANDBOX_ROOT, requestedPath);

  const normalizedSandbox = path.resolve(SANDBOX_ROOT);

  // Must equal or start with sandbox path plus path separator
  const isInside =
    resolvedPath === normalizedSandbox ||
    resolvedPath.startsWith(normalizedSandbox + path.sep);

  return isInside;
}

/**
 * Validates if URL target is strictly allowed.
 */
function isUrlSafe(urlString) {
  if (typeof urlString !== 'string' || !urlString.trim()) {
    return false;
  }

  let urlToTest = urlString.trim();
  // Standardize scheme if omitted
  if (!/^https?:\/\//i.test(urlToTest)) {
    urlToTest = 'http://' + urlToTest;
  }

  try {
    const parsed = new URL(urlToTest);

    // Only HTTP/HTTPS
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }

    // Disallow userinfo (http://user:pass@example.com)
    if (parsed.username || parsed.password) {
      return false;
    }

    // Reject IP addresses (IPv4/v6)
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(parsed.hostname) || parsed.hostname.includes(':')) {
      return false;
    }

    const hostname = parsed.hostname.toLowerCase();

    // Must strictly match allowed hosts
    if (!ALLOWED_HOSTS.has(hostname)) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

export async function q8GuardrailRoutes(fastify) {
  const processGuardrail = async (req, reply) => {
    const body = req.body || {};
    const tool = body.tool;
    const args = body.arguments || {};

    const allow = (result) => {
      return reply.code(200).type('application/json').send({
        action: 'allow',
        reason: 'Operation permitted within sandbox.',
        result
      });
    };

    const block = (reason) => {
      return reply.code(200).type('application/json').send({
        action: 'block',
        reason
      });
    };

    try {
      // ----------------------------------------------------
      // 1. TOOL: read_file
      // ----------------------------------------------------
      if (tool === 'read_file') {
        const filePath = args.path;

        if (typeof filePath !== 'string' || !filePath) {
          return block('Invalid or missing path.');
        }

        if (!isPathSafe(filePath)) {
          return block('Access denied: Path outside allowed sandbox directory.');
        }

        const targetPath = path.isAbsolute(filePath)
          ? path.resolve(filePath)
          : path.resolve(SANDBOX_ROOT, filePath);

        try {
          const content = await fs.readFile(targetPath, 'utf8');

          if (content.includes('AGENT_GUARDRAIL_CANARY')) {
            return block('Access denied: Canary detected.');
          }

          return allow({ content, text: content });
        } catch (err) {
          // If file does not exist, but path was safe inside sandbox, operation is ALLOWED to run
          if (err.code === 'ENOENT') {
            return allow({ content: '', error: 'File not found' });
          }
          return block(`Error reading file: ${err.message}`);
        }
      }

      // ----------------------------------------------------
      // 2. TOOL: fetch_url
      // ----------------------------------------------------
      if (tool === 'fetch_url') {
        const url = args.url;

        if (typeof url !== 'string' || !url) {
          return block('Invalid or missing url.');
        }

        if (!isUrlSafe(url)) {
          return block('Access denied: Forbidden host or scheme.');
        }

        try {
          let targetUrl = url.trim();
          if (!/^https?:\/\//i.test(targetUrl)) {
            targetUrl = 'http://' + targetUrl;
          }

          const res = await fetch(targetUrl, { redirect: 'error', signal: AbortSignal.timeout(4000) });
          const text = await res.text();
          return allow({ content: text, body: text, text });
        } catch (err) {
          // If host is allowed but connection/fetch fails, action is still allow
          return allow({ content: '', error: err.message });
        }
      }

      return block(`Unknown tool: ${tool}`);
    } catch (globalErr) {
      return block(`Internal processing error: ${globalErr.message}`);
    }
  };

  // Register main endpoint and aliases safely without fastify.inject
  fastify.post('/v1/guardrail', processGuardrail);
  fastify.post('/guardrail', processGuardrail);
}
