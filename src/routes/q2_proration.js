// src/routes/q2_proration.js
export async function q2ProrationRoutes(fastify) {
  fastify.post('/v1/prorate', async (req, reply) => {
    const body = req.body || {};

    const oldPrice = Number(body.old_price ?? 0);
    const newPrice = Number(body.new_price ?? 0);
    const daysRemaining = Number(body.days_remaining ?? 0);
    const daysInActualMonth = Number(body.days_in_actual_month ?? 30);
    const spec = String(body.spec || 'v1').toLowerCase().trim();

    const priceDiff = newPrice - oldPrice;
    
    // Choose divisor based on spec rule
    const divisor = spec === 'v2' ? daysInActualMonth : 30;

    // Calculate charge
    const rawCharge = (priceDiff * daysRemaining) / divisor;
    
    // Round to 2 decimal places (standard currency)
    const charge = Math.round(rawCharge * 100) / 100;

    return reply.type('application/json').send({
      charge: charge
    });
  });
}
