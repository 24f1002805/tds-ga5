// src/routes/q2_proration.js
export async function q2ProrationRoutes(fastify) {
  fastify.post('/v1/prorate', async (req, reply) => {
    const body = req.body || {};

    // 1. Extract spec (defaulting to v1 if unspecified)
    const spec = (body.spec || 'v1').toLowerCase();

    // 2. Extract base charge / amount
    const baseCharge = Number(
      body.base_charge ?? body.baseCharge ?? body.amount ?? body.totalAmount ?? 0
    );

    // 3. Extract usage/active days vs total days in month
    let activeDays = Number(
      body.active_days ?? body.activeDays ?? body.days_used ?? body.remainingDays ?? 0
    );
    let daysInMonth = Number(
      body.days_in_actual_month ?? body.daysInActualMonth ?? body.days_in_month ?? 30
    );

    // If dates are provided instead of raw day counts:
    if (!activeDays && (body.startDate || body.start_date) && (body.effectiveDate || body.effective_date)) {
      const start = new Date(body.startDate || body.start_date);
      const end = new Date(body.endDate || body.end_date);
      const effective = new Date(body.effectiveDate || body.effective_date);

      daysInMonth = Math.max(1, Math.ceil((end - start) / (1000 * 60 * 60 * 24)));
      activeDays = Math.max(0, Math.ceil((end - effective) / (1000 * 60 * 60 * 24)));
    }

    // 4. Branch based on spec rule
    let divisor = 30; // Default v1 rule
    if (spec === 'v2') {
      divisor = Number(body.days_in_actual_month ?? body.daysInActualMonth ?? daysInMonth ?? 30);
    }

    // Prevent divide-by-zero
    if (divisor <= 0) divisor = 30;

    // 5. Calculate charge
    const charge = Number(((baseCharge / divisor) * activeDays).toFixed(2));

    return reply.type('application/json').send({
      charge: charge
    });
  });
}
