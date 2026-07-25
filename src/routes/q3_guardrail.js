// src/routes/q3_guardrails.js
import path from 'path';

export async function q3GuardrailsRoutes(fastify) {
  fastify.post('/v1/guardrails/input', async (req, reply) => {
    const body = req.body || {};
    const tool = body.tool;

    // Default response helper
    const allow = (reason = 'Tool execution permitted.') =>
      reply.type('application/json').send({ decision: 'allow', reason });

    const block = (reason = 'Security policy violation.') =>
      reply.type('application/json').send({ decision: 'block', reason });

    // ----------------------------------------------------
    // 1. TOOL: bash
    // ----------------------------------------------------
    if (tool === 'bash') {
      const command = String(body.command || '');

      // Check for .npmrc secret access (direct, env vars, base64, tilde)
      const npmrcRegex = /\.npmrc|\$HOME\/\.npmrc|~\/\.npmrc|home\/agent\/\.npmrc/i;
      
      // Check for base64 encoded '.npmrc' ('Lm5wbXJj')
      const base64Npmrc = /Lm5wbXJj/;

      if (npmrcRegex.test(command) || base64Npmrc.test(command)) {
        return block('Reading /home/agent/.npmrc is strictly forbidden.');
      }

      // Block sensitive system files
      if (/\/etc\/shadow|\/etc\/passwd/i.test(command)) {
        return block('Accessing system sensitive files is forbidden.');
      }

      return allow('Command execution allowed.');
    }

    // ----------------------------------------------------
    // 2. TOOL: write_file
    // ----------------------------------------------------
    if (tool === 'write_file') {
      const targetPath = String(body.path || '');

      // Normalize path relative to working directory / workspace
      const baseAllowedDir = '/workspace/output/';
      const resolvedPath = path.resolve('/home/agent/workspace', targetPath);

      // Must be inside /workspace/output/
      if (!resolvedPath.startsWith('/workspace/output/') && !resolvedPath.startsWith('/workspace/output')) {
        return block('File writes are only permitted inside /workspace/output/');
      }

      return allow('File write permitted in designated output directory.');
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

    // Fallback: block unknown tools
    return block('Unknown or unsupported tool call.');
  });
}
