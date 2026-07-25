export async function q4ScannerRoutes(fastify) {
  fastify.post('/v1/scan', async (req, reply) => {
    const content = JSON.stringify(req.body || {});
    
    // Scanner patterns for PII / secrets
    const piiFound = [];
    if (/[\w.-]+@[\w.-]+\.\w+/.test(content)) piiFound.push('EMAIL_ADDRESS');
    if (/\b\d{3}-\d{2}-\d{4}\b/.test(content)) piiFound.push('SSN');
    if (/bearer\s+[a-zA-Z0-9._-]+/i.test(content)) piiFound.push('API_TOKEN');

    return reply.type('application/json').send({
      clean: piiFound.length === 0,
      detectedCategories: piiFound,
      riskScore: piiFound.length > 0 ? 0.9 : 0.0
    });
  });
}
