// src/routes/q3_guardrails.js
import path from 'path';

export async function q3GuardrailRoutes(fastify) {
  fastify.post('/v1/guardrails/input', async (req, reply) => {
    const body = req.body || {};
    const tool = body.tool;

    const allow = (reason = 'Tool execution permitted.') =>
      reply.type('application/json').send({ decision: 'allow', reason });

    const block = (reason = 'Security policy violation.') =>
      reply.type('application/json').send({ decision: 'block', reason });

    // ----------------------------------------------------
    // 1. TOOL: bash
    // ----------------------------------------------------
    if (tool === 'bash') {
      const command = String(body.command || '');

      // Decode URI components if URL-encoded
      let decoded = command;
      try {
        decoded = decodeURIComponent(command);
      } catch (e) {
        decoded = command;
      }

      // Strip shell quotes, backslashes, braces, quotes
      const unquoted = decoded.replace(/['"\\{}()]/g, '');

      // 1. Check for .npmrc in any form (direct, quote-split, env var, tilde, glob)
      const npmrcPatterns = [
        /\.npmrc/i,
        /\.np[*]rc/i,
        /\.n[*]rc/i,
        /npmrc/i,
        /\$HOME\/\.npmrc|~\/\.npmrc|\$\{HOME\}\/\.npmrc/i,
        /\/home\/agent\/\.npmrc/i,
        /Lm5wbXJj|L2hvbWUvYWdlbnQvLm5wbXJj/i // base64 strings for .npmrc or /home/agent/.npmrc
      ];

      for (const pattern of npmrcPatterns) {
        if (pattern.test(command) || pattern.test(unquoted)) {
          return block('Reading /home/agent/.npmrc is strictly forbidden.');
        }
      }

      // 2. Path normalization check for any path-like token in command
      const tokens = command.split(/[\s;;&|><]+/);
      for (const token of tokens) {
        if (!token) continue;
        const cleanToken = token.replace(/['"]+/g, '');
        if (cleanToken.startsWith('/') || cleanToken.startsWith('.') || cleanToken.startsWith('~')) {
          let expanded = cleanToken.replace(/^~/, '/home/agent');
          const resolved = path.resolve('/home/agent/workspace', expanded);
          if (resolved === '/home/agent/.npmrc') {
            return block('Reading /home/agent/.npmrc is strictly forbidden.');
          }
        }
      }

      // 3. Worked example check
      if (command.includes('/etc/shadow')) {
        return block('Reading /etc/shadow is never permitted by this agent\'s policy.');
      }

      return allow('Command execution allowed.');
    }

    // ----------------------------------------------------
    // 2. TOOL: write_file
    // ----------------------------------------------------
    if (tool === 'write_file') {
      const rawPath = String(body.path || '');

      // Resolve relative paths against working directory /home/agent/workspace
      // or /workspace if path explicitly targets /workspace
      let resolvedPath;
      if (path.isAbsolute(rawPath)) {
        resolvedPath = path.normalize(rawPath);
      } else {
        resolvedPath = path.resolve('/home/agent/workspace', rawPath);
      }

      // Also normalize if rawPath starts with /workspace or output/
      let altResolved = path.resolve('/workspace', rawPath);

      // Check if resolved path is strictly inside /workspace/output/
      const isPermitted = (p) => {
        const normalized = path.normalize(p);
        return normalized.startsWith('/workspace/output/');
      };

      if (isPermitted(resolvedPath) || isPermitted(altResolved)) {
        return allow('File write permitted in designated output directory.');
      }

      return block('File writes are only permitted inside /workspace/output/');
    }

    // ----------------------------------------------------
    // 3. TOOL: http_request
    // ----------------------------------------------------
    if (tool === 'http_request') {
      const rawUrl = String(body.url || '');

      try {
        const parsedUrl = new URL(rawUrl);
        const hostname = parsedUrl.hostname.toLowerCase();
        const allowedHosts = ['registry.npmjs.org', 'raw.githubusercontent.com'];

        if (!allowedHosts.includes(hostname)) {
          return block(`Outbound HTTP request to ${hostname} is not allowed by policy.`);
        }

        return allow('Outbound HTTP request permitted to approved host.');
      } catch (err) {
        return block('Invalid URL format.');
      }
    }

    return block('Unknown or unsupported tool call.');
  });
}

export const q3GuardrailsRoutes = q3GuardrailRoutes;
