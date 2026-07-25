// src/routes/q2_proration.js
export async function q2ProrationRoutes(fastify) {
  fastify.post('/v1/prorate', async (req, reply) => {
    const body = req.body || {};

    // 1. Determine Spec ("v1" or "v2")
    const spec = String(body.spec || 'v1').toLowerCase().trim();

    // 2. Extract Base Charge / Total Amount
    const baseCharge = Number(
      body.base_charge ?? body.baseCharge ?? body.amount ?? body.total_amount ?? body.totalAmount ?? body.price ?? 0
    );

    // 3. Extract Divisor
    let divisor = 30; // Default for v1
    const actualMonthDays = Number(
      body.days_in_actual_month ?? body.daysInActualMonth ?? body.days_in_month ?? body.total_days ?? 30
    );

    if (spec === 'v2') {
      divisor = actualMonthDays > 0 ? actualMonthDays : 30;
    } else {
      divisor = 30; // Force exactly 30 for v1
    }

    // 4. Extract Active / Used Days
    let activeDays = null;

    if (body.active_days !== undefined) activeDays = Number(body.active_days);
    else if (body.days_used !== undefined) activeDays = Number(body.days_used);
    else if (body.used_days !== undefined) activeDays = Number(body.used_days);
    else if (body.remaining_days !== undefined) activeDays = Number(body.remaining_days);

    // If activeDays wasn't directly passed, compute from dates
    if (activeDays === null) {
      const startStr = body.start_date || body.startDate || body.billing_cycle_start;
      const endStr = body.end_date || body.endDate || body.billing_cycle_end;
      const effectiveStr = body.effective_date || body.effectiveDate || body.change_date || body.cancel_date;

      if (startStr && effectiveStr) {
        const start = new Date(startStr);
        const effective = new Date(effectiveStr);
        const end = endStr ? new Date(endStr) : null;

        // Calculate days between effective date and end date (or start date and effective date)
        const msPerDay = 1000 * 60 * 60 * 24;
        if (end && effective <= end) {
          activeDays = Math.round((end - effective) / msPerDay);
        } else {
          activeDays = Math.round((effective - start) / msPerDay);
        }
      }
    }

    if (activeDays === null || isNaN(activeDays)) {
      activeDays = 0;
    }

    // 5. Calculate Charge
    const rawCharge = (baseCharge / divisor) * activeDays;
    const charge = Math.round(rawCharge * 100) / 100;

    return reply.type('application/json').send({
      charge: charge
    });
  });
}
