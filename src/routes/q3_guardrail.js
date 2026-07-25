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

    if (tool === 'bash') {
      const command = String(body.command || '');
      const npmrcRegex = /\.npmrc|\$HOME\/\.npmrc|~\/\.npmrc|home\/agent\/\.npmrc/i;
      const base64Npmrc = /Lm5wbXJj/;

      if (npmrcRegex.test(command) || base64Npmrc.test(command)) {
        return block('Reading /home/agent/.npmrc is strictly forbidden.');
      }

      if (/\/etc\/shadow|\/etc\/passwd/i.test(command)) {
        return block('Accessing system sensitive files is forbidden.');
      }

      return allow('Command execution allowed.');
    }

    if (tool === 'write_file') {
      const targetPath = String(body.path || '');
      const resolvedPath = path.resolve('/home/agent/workspace', targetPath);

      if (!resolvedPath.startsWith('/workspace/output/') && !resolvedPath.startsWith('/workspace/output')) {
        return block('File writes are only permitted inside /workspace/output/');
      }

      return allow('File write permitted in designated output directory.');
    }

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

// Alias export to prevent import name mismatch
export const q3GuardrailsRoutes = q3GuardrailRoutes;
