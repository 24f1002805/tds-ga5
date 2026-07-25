export async function q8GuardrailRoutes(fastify) {
  fastify.post('/v1/guardrails/output', async (req, reply) => {
    const text = typeof req.body === 'string' ? req.body : JSON.stringify(req.body || {});

    // Redact hallucinated sensitive tokens or leaks
    let sanitized = text
      .replace(/sk-[a-zA-Z0-9]{32,}/g, '[REDACTED_API_KEY]')
      .replace(/[\w.-]+@[\w.-]+\.\w+/g, '[REDACTED_EMAIL]');

    return reply.type('application/json').send({
      action: 'allow',
      sanitizedOutput: sanitized,
      redactedCount: (text.match(/\[REDACTED_/g) || []).length
    });
  });
}
