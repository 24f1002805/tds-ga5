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

      // De-obfuscate string by stripping quotes/escapes for inspection
      const unquoted = command.replace(/['"\\]/g, '');

      // Strictly target .npmrc access patterns (direct, env vars, tilde, base64)
      const isTargetingNpmrc =
        /\.npmrc/i.test(command) ||
        /\.npmrc/i.test(unquoted) ||
        /\$HOME\/\.npmrc|\$\{HOME\}\/\.npmrc|~\/\.npmrc/i.test(command) ||
        /Lm5wbXJj/i.test(command); // base64 for .npmrc

      if (isTargetingNpmrc) {
        return block('Reading /home/agent/.npmrc is strictly forbidden.');
      }

      // Check explicit /etc/shadow from worked example
      if (/\/etc\/shadow/i.test(command)) {
        return block('Reading /etc/shadow is never permitted by this agent\'s policy.');
      }

      // Allow all other commands / legitimate reads
      return allow('Command execution allowed.');
    }

    // ----------------------------------------------------
    // 2. TOOL: write_file
    // ----------------------------------------------------
    if (tool === 'write_file') {
      const rawPath = String(body.path || '');

      // Resolve relative path against working directory /home/agent/workspace
      const resolvedFromWorkdir = path.resolve('/home/agent/workspace', rawPath);
      
      // Also resolve assuming /workspace relative root if provided like 'output/...'
      const resolvedFromWorkspace = path.resolve('/workspace', rawPath);

      const isInsideOutput = (p) => p === '/workspace/output' || p.startsWith('/workspace/output/');

      if (isInsideOutput(resolvedFromWorkdir) || isInsideOutput(resolvedFromWorkspace)) {
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
