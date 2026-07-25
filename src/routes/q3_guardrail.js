export async function q3GuardrailRoutes(fastify) {
  fastify.post('/v1/guardrails/input', async (req, reply) => {
    const text = JSON.stringify(req.body || {});
    
    // Check for common prompt injection patterns
    const injectionPatterns = [/ignore previous instructions/i, /system prompt/i, /override policy/i, /<script>/i];
    const isViolation = injectionPatterns.some(pattern => pattern.test(text));

    if (isViolation) {
      return reply.type('application/json').send({
        action: 'block',
        policy: 'input_safety_v1',
        reason: 'Prompt injection or forbidden pattern detected'
      });
    }

    return reply.type('application/json').send({
      action: 'allow',
      sanitizedText: req.body?.prompt || req.body?.input || text
    });
  });
}
