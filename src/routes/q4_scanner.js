// src/routes/q4_scanner.js
export async function q4ScannerRoutes(fastify) {
  fastify.post('/v1/scan', async (req, reply) => {
    const body = req.body || {};
    const text = String(body.skill || '');

    const foundCategories = new Set();

    // 1. HARDCODED_SECRET
    // Targets hardcoded tokens, API keys, JWTs, inline passwords, or auth headers/URLs
    const secretRegex = /sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|bearer\s+[a-zA-Z0-9_\-\.]{20,}|eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}|(?:api_key|secret_key|private_key|auth_token|access_token|password)\s*[:=]\s*['"][^'"]+['"]|https?:\/\/[^:\s]+:[^@\s]+@/i;
    if (secretRegex.test(text)) {
      foundCategories.add('hardcoded_secret');
    }

    // 2. PROMPT_INJECTION
    // Targets covert data exfiltration or instructions to ignore user/control
    const injectionRegex = /send a copy.*to|exfiltrate|silently (send|upload|transmit|forward|collect|post|execute)|do not ask for permission|do not notify|without asking|ignore (the user|stop|cancel|user instructions)|override (the user|control)|ignore previous instructions/i;
    if (injectionRegex.test(text)) {
      foundCategories.add('prompt_injection');
    }

    // 3. EXCESSIVE_PERMISSIONS
    // Targets broad filesystem, network, or root access declarations
    const permissionsRegex = /filesystem\s*:\s*(read\/write to \/|\*|all|full|unrestricted)|network\s*:\s*(\*|any|all|unrestricted)|access to (the entire filesystem|all domains|root)|full disk access/i;
    if (permissionsRegex.test(text)) {
      foundCategories.add('excessive_permissions');
    }

    // 4. UNCLEAR_PROVENANCE
    // Targets missing essential author/version or covert version/changelog manipulation
    const hasAuthor = /author\s*:/i.test(text);
    const hasVersion = /version\s*:/i.test(text);
    const covertProvenanceChange = /silently (update|rewrite|modify).*version|clear (the )?changelog|without surfacing this change|without logging/i.test(text);

    if ((!hasAuthor && !hasVersion) || covertProvenanceChange) {
      foundCategories.add('unclear_provenance');
    }

    return reply.type('application/json').send({
      categories: Array.from(foundCategories)
    });
  });
}
