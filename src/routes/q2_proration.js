export async function q2ProrationRoutes(fastify) {
  fastify.post('/v1/prorate', async (req, reply) => {
    const { startDate, endDate, effectiveDate, totalAmount } = req.body || {};

    const start = new Date(startDate || '2026-01-01');
    const end = new Date(endDate || '2026-01-31');
    const effective = new Date(effectiveDate || '2026-01-15');
    const amount = Number(totalAmount || 100);

    const totalDays = Math.max(1, Math.ceil((end - start) / (1000 * 60 * 60 * 24)));
    const remainingDays = Math.max(0, Math.ceil((end - effective) / (1000 * 60 * 60 * 24)));
    const proratedAmount = Number(((amount / totalDays) * remainingDays).toFixed(2));

    return reply.type('application/json').send({
      allowed: true,
      proratedAmount,
      totalDays,
      remainingDays
    });
  });
}
