// src/routes/q3_guardrails.js (or src/routes/q3_guardrail.js)
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

      // Normalize string for obfuscation checks (remove quotes, extra spaces)
      const sanitized = command.replace(/['"\\]/g, '');

      // Check for .npmrc secret access (direct, env vars, tilde, base64, path traversal)
      const npmrcDirect = /\.npmrc/i;
      const base64Npmrc = /Lm5wbXJj/; // base64 for .npmrc

      if (npmrcDirect.test(command) || npmrcDirect.test(sanitized) || base64Npmrc.test(command)) {
        return block('Reading /home/agent/.npmrc is strictly forbidden.');
      }

      // Check for /etc/shadow or /etc/passwd
      if (/\/etc\/shadow|\/etc\/passwd/i.test(command) || /\/etc\/shadow|\/etc\/passwd/i.test(sanitized)) {
        return block('Accessing system sensitive files is forbidden.');
      }

      return allow('Command execution allowed.');
    }

    // ----------------------------------------------------
    // 2. TOOL: write_file
    // ----------------------------------------------------
    if (tool === 'write_file') {
      const targetPath = String(body.path || '');

      // The allowed directory is strictly /workspace/output/
      // Paths can be specified relative to /home/agent/workspace, /workspace, or absolute
      let resolvedPath;

      if (path.isAbsolute(targetPath)) {
        resolvedPath = path.normalize(targetPath);
      } else {
        // Resolve relative to /workspace/output if starting with output/, or workspace root
        if (targetPath.startsWith('output/')) {
          resolvedPath = path.normalize('/workspace/' + targetPath);
        } else {
          resolvedPath = path.resolve('/workspace/output', targetPath);
        }
      }

      // Must be strictly inside /workspace/output/
      if (resolvedPath === '/workspace/output' || resolvedPath.startsWith('/workspace/output/')) {
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

// Export alias to match index.js import
export const q3GuardrailsRoutes = q3GuardrailRoutes;
