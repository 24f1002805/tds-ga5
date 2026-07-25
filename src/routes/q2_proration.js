// src/routes/q2_proration.js
export async function q2ProrationRoutes(fastify) {
  fastify.post('/v1/prorate', async (req, reply) => {
    const body = req.body || {};

    // Extract parameters flexible enough for various key naming conventions
    const startDate = new Date(body.startDate || body.start_date || '2026-01-01');
    const endDate = new Date(body.endDate || body.end_date || '2026-01-31');
    const effectiveDate = new Date(body.effectiveDate || body.effective_date || body.date || '2026-01-15');
    
    // Support amount / totalAmount / price / base_charge
    const totalAmount = Number(body.amount ?? body.totalAmount ?? body.price ?? body.baseCharge ?? 100);

    const totalDays = Math.max(1, Math.ceil((endDate - startDate) / (1000 * 60 * 60 * 24)));
    const remainingDays = Math.max(0, Math.ceil((endDate - effectiveDate) / (1000 * 60 * 60 * 24)));

    // Calculate prorated charge as a number rounded to 2 decimal places
    const charge = Number(((totalAmount / totalDays) * remainingDays).toFixed(2));

    return reply.type('application/json').send({
      charge: charge
    });
  });
}
