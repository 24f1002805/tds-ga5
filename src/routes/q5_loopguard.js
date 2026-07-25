import { getDb } from '../db.js';

export async function q5LoopGuardRoutes(fastify) {
  fastify.post('/v1/loop-guard', async (req, reply) => {
    const { runId, action, cost = 0.01, maxSteps = 10, maxBudget = 1.00 } = req.body || {};
    if (!runId) return reply.code(400).send({ error: 'Missing runId' });

    const db = getDb();
    const existing = await db.get('SELECT * FROM q5_executions WHERE runId = ?', [runId]);

    let stepCount = existing ? existing.stepCount + 1 : 1;
    let spentBudget = existing ? existing.spentBudget + Number(cost) : Number(cost);

    if (stepCount > maxSteps || spentBudget > maxBudget) {
      return reply.type('application/json').send({
        action: 'terminate',
        reason: stepCount > maxSteps ? 'MAX_STEPS_EXCEEDED' : 'BUDGET_EXCEEDED',
        stepCount,
        spentBudget
      });
    }

    await db.run(
      'INSERT OR REPLACE INTO q5_executions (runId, stepCount, spentBudget, historyJson) VALUES (?, ?, ?, ?)',
      [runId, stepCount, spentBudget, JSON.stringify({ lastAction: action })]
    );

    return reply.type('application/json').send({
      action: 'continue',
      stepCount,
      spentBudget
    });
  });
}
