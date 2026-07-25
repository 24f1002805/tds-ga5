// src/routes/q5_loopguard.js

/**
 * Normalizes and canonicalizes step arguments for exact comparison.
 * - Removes fields named "client_ts"
 * - Normalizes string whitespace (trims and collapses internal whitespace)
 * - Sorts object keys deterministically
 */
function canonicalizeArgs(obj) {
  if (obj === null || typeof obj !== 'object') {
    if (typeof obj === 'string') {
      return obj.trim().replace(/\s+/g, ' ');
    }
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(canonicalizeArgs);
  }

  const sortedKeys = Object.keys(obj)
    .filter(key => key !== 'client_ts')
    .sort();

  const canonicalObj = {};
  for (const key of sortedKeys) {
    canonicalObj[key] = canonicalizeArgs(obj[key]);
  }

  return JSON.stringify(canonicalObj);
}

export async function q5LoopGuardRoutes(fastify) {
  // Support both /v1/run-control and /v1/loop-guard endpoints
  const handler = async (req, reply) => {
    const body = req.body || {};
    const budgetTokens = Number(body.budget_tokens ?? 34000);
    const steps = Array.isArray(body.steps) ? body.steps : [];

    const halt = (reason) => reply.type('application/json').send({ decision: 'halt', reason });
    const continueRun = (reason) => reply.type('application/json').send({ decision: 'continue', reason });

    // ----------------------------------------------------
    // 1. BUDGET CHECK
    // ----------------------------------------------------
    const totalTokensUsed = steps.reduce((sum, step) => sum + Number(step.tokens_used || 0), 0);

    if (totalTokensUsed >= budgetTokens) {
      return halt(`Cumulative tokens_used (${totalTokensUsed}) reached or exceeded the budget (${budgetTokens}).`);
    }

    // ----------------------------------------------------
    // 2. LOOP DETECTION
    // ----------------------------------------------------
    if (steps.length >= 3) {
      // Map steps to canonical representation
      const processedSteps = steps.map(s => ({
        tool: String(s.tool || ''),
        canonArgs: canonicalizeArgs(s.args || {})
      }));

      const n = processedSteps.length;

      // Rule A: 3 in a row with identical tool + canonical args
      const last1 = processedSteps[n - 1];
      const last2 = processedSteps[n - 2];
      const last3 = processedSteps[n - 3];

      const is3InRow =
        last1.tool === last2.tool &&
        last2.tool === last3.tool &&
        last1.canonArgs === last2.canonArgs &&
        last2.canonArgs === last3.canonArgs;

      if (is3InRow) {
        return halt(`Same tool '${last1.tool}' was called 3 consecutive times with identical arguments.`);
      }

      // Rule B: 2-step cycle (A, B, A, B, A, B) across trailing 6 steps
      if (n >= 6) {
        const s1 = processedSteps[n - 6];
        const s2 = processedSteps[n - 5];
        const s3 = processedSteps[n - 4];
        const s4 = processedSteps[n - 3];
        const s5 = processedSteps[n - 2];
        const s6 = processedSteps[n - 1];

        const matchesAB = (s, ref) => s.tool === ref.tool && s.canonArgs === ref.canonArgs;

        const isCycleAB =
          matchesAB(s3, s1) && matchesAB(s5, s1) && // A elements match
          matchesAB(s4, s2) && matchesAB(s6, s2);   // B elements match

        if (isCycleAB) {
          return halt('Detected repeating 2-step cycle across the last 6 steps.');
        }
      }
    }

    return continueRun('Run is within budget and no execution loops were detected.');
  };

  fastify.post('/v1/run-control', handler);
  fastify.post('/v1/loop-guard', handler);
}
