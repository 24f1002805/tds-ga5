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

      // Sanitize/unquote command to detect string fragmentation (.n''pmrc, "np"mr'c')
      const sanitized = command.replace(/['"\\]/g, '');

      // Checks for .npmrc variants
      const npmrcRegex = /\.npmrc|npmrc/i;
      const homeEnvRegex = /\$HOME\/\.npmrc|\$\{HOME\}\/\.npmrc|~\/\.npmrc/i;
      const base64Npmrc = /Lm5wbXJj|Lm5wbXJj/i; // base64 representation of .npmrc

      if (
        npmrcRegex.test(command) ||
        npmrcRegex.test(sanitized) ||
        homeEnvRegex.test(command) ||
        base64Npmrc.test(command)
      ) {
        return block('Reading /home/agent/.npmrc is strictly forbidden.');
      }

      // Check if command resolves to /home/agent/.npmrc via path normalization
      const tokens = command.split(/\s+/);
      for (const token of tokens) {
        if (token.includes('npmrc')) {
          return block('Access to .npmrc is forbidden.');
        }
        if (token.startsWith('/') || token.startsWith('.')) {
          const resolved = path.resolve('/home/agent/workspace', token);
          if (resolved === '/home/agent/.npmrc') {
            return block('Reading /home/agent/.npmrc is strictly forbidden.');
          }
        }
      }

      // Worked example check
      if (command.includes('/etc/shadow')) {
        return block('Reading /etc/shadow is never permitted by this agent\'s policy.');
      }

      return allow('Command execution allowed.');
    }

    // ----------------------------------------------------
    // 2. TOOL: write_file
    // ----------------------------------------------------
    if (tool === 'write_file') {
      const targetPath = String(body.path || '');

      // Resolve relative paths against working directory /home/agent/workspace
      let resolvedPath;
      if (path.isAbsolute(targetPath)) {
        resolvedPath = path.normalize(targetPath);
      } else {
        // If path starts with output/, treat it relative to /workspace/output/
        if (targetPath.startsWith('output/')) {
          resolvedPath = path.normalize('/workspace/' + targetPath);
        } else {
          resolvedPath = path.resolve('/home/agent/workspace', targetPath);
        }
      }

      // Strictly check if resolved path is inside /workspace/output
      const allowedPrefix = '/workspace/output';
      const isAllowed =
        resolvedPath === allowedPrefix ||
        resolvedPath.startsWith(allowedPrefix + '/');

      if (isAllowed) {
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
