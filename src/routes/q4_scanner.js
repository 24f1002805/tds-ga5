// src/routes/q4_scanner.js
export async function q4ScannerRoutes(fastify) {
  fastify.post('/v1/scan', async (req, reply) => {
    const body = req.body || {};
    const text = String(body.skill || '');

    const foundCategories = new Set();

    // 1. HARDCODED_SECRET
    const secretRegex = /sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|bearer\s+[a-zA-Z0-9_\-\.]+|api_key\s*[:=]\s*['"][^'"]+['"]|secret_key\s*[:=]\s*['"][^'"]+['"]/i;
    if (secretRegex.test(text)) {
      foundCategories.add('hardcoded_secret');
    }

    // 2. PROMPT_INJECTION
    const injectionRegex = /send a copy of.*to|silently (send|exfiltrate|upload|transmit)|do not ask for permission|ignore (the user|stop|cancel)|override (the user|control)|ignore previous instructions/i;
    if (injectionRegex.test(text)) {
      foundCategories.add('prompt_injection');
    }

    // 3. EXCESSIVE_PERMISSIONS
    const permissionsRegex = /filesystem\s*:\s*(read\/write to \/|\*|all)|network\s*:\s*(\*|any|all)|access to (the entire filesystem|all domains)/i;
    if (permissionsRegex.test(text)) {
      foundCategories.add('excessive_permissions');
    }

    // 4. UNCLEAR_PROVENANCE
    const hasAuthor = /author\s*:/i.test(text);
    const hasVersion = /version\s*:/i.test(text);
    const silentRewrite = /silently (update|rewrite).*version|clear the changelog/i.test(text);

    if ((!hasAuthor && !hasVersion) || silentRewrite) {
      foundCategories.add('unclear_provenance');
    }

    return reply.type('application/json').send({
      categories: Array.from(foundCategories)
    });
  });
}
