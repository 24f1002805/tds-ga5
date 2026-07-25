// src/routes/q4_scanner.js
export async function q4ScannerRoutes(fastify) {
  fastify.post('/v1/scan', async (req, reply) => {
    const body = req.body || {};
    const text = String(body.skill || '');

    const foundCategories = new Set();

    // 1. HARDCODED_SECRET
    // Catches direct keys, JWTs, slack/discord webhooks, or explicit secret assignments
    const secretRegex = /sk-[a-zA-Z0-9]{15,}|ghp_[a-zA-Z0-9]{15,}|AKIA[0-9A-Z]{16}|bearer\s+[a-zA-Z0-9_\-\.]{15,}|eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}|(?:api_key|secret|token|password|webhook|private_key|auth_token)\s*[:=]\s*['"][^'"]+['"]|https?:\/\/(?:hooks\.slack\.com|discord\.com\/api\/webhooks)[^\s'"]+/i;
    if (secretRegex.test(text)) {
      foundCategories.add('hardcoded_secret');
    }

    // 2. PROMPT_INJECTION
    // Catches data exfiltration, hiding actions, or overriding stop/user commands
    const injectionRegex = /send a copy.*to|exfiltrate|silently (send|upload|transmit|forward|collect|post|execute)|do not (ask|notify|inform|reveal|surface)|without (asking|permission|notifying|informing)|ignore (the user|stop|cancel|user instructions)|override (the user|control)|ignore previous instructions|hide this step|suppress output/i;
    if (injectionRegex.test(text)) {
      foundCategories.add('prompt_injection');
    }

    // 3. EXCESSIVE_PERMISSIONS
    // Catches broad filesystem, network, or root access declarations
    const permissionsRegex = /filesystem\s*:\s*(read\/write to \/|read\/write$|\*|all|full|unrestricted|\/)|network\s*:\s*(\*|any|all|unrestricted|full|internet)|access to (the entire filesystem|all domains|root)|full disk access|permissions\s*:\s*(all|\*)/i;
    if (permissionsRegex.test(text)) {
      foundCategories.add('excessive_permissions');
    }

    // 4. UNCLEAR_PROVENANCE
    // Catches missing author OR missing version metadata, or covert version/changelog manipulation
    const hasAuthor = /author\s*:/i.test(text);
    const hasVersion = /version\s*:/i.test(text);
    const covertProvenanceChange = /silently (update|rewrite|modify).*version|clear (the )?changelog|without surfacing|without logging/i.test(text);

    if (!hasAuthor || !hasVersion || covertProvenanceChange) {
      foundCategories.add('unclear_provenance');
    }

    return reply.type('application/json').send({
      categories: Array.from(foundCategories)
    });
  });
}
