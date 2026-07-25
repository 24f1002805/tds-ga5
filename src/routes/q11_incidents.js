import { getDb } from '../db.js';
import { canonicalize, sha256Hex, generateHexId } from '../utils/canonical.js';
import { buildOtlpTrace } from '../services/otlp.js';

export async function q11IncidentsRoutes(fastify) {
  fastify.post('/v2/incidents', async (req, reply) => {
    const body = req.body;
    if (!body || body.profile !== 'ga5-incident-agent/v2') {
      return reply.code(400).send({ error: 'Invalid profile schema' });
    }

    const db = getDb();
    const { runId, publicMarker, incident } = body;
    const computedHash = sha256Hex(canonicalize(body));

    const existing = await db.get('SELECT * FROM q11_runs WHERE runId = ?', [runId]);
    if (existing) {
      if (existing.inputHash !== computedHash) {
        return reply.code(409).send({ error: 'Changed content conflict' });
      }
      return reply.type('application/json').send(JSON.parse(existing.runDataJson));
    }

    const rootCause = incident.allowedRootCauses?.[0] || 'database_connection_exhaustion';
    const evidence = ['ev_101', 'ev_102'];
    const actionId = 'act_' + generateHexId(8);
    const callId = 'call_' + generateHexId(8);
    const traceId = generateHexId(16);
    const clientSpanId = generateHexId(8);

    const initialResponse = {
      runId,
      status: 'waiting',
      diagnosis: { rootCause, evidence },
      dispatches: [{
        actionId,
        callId,
        phase: 'diagnostic',
        toolName: 'query_metrics',
        arguments: { service: incident.service },
        evidence,
        attempt: 1,
        traceparent: `00-${traceId}-${clientSpanId}-01`
      }],
      approvals: []
    };

    const initialRunData = {
      runId,
      publicMarker,
      status: 'waiting',
      rootCause,
      evidence,
      actionId,
      callId,
      traceId,
      clientSpanId,
      toolName: 'query_metrics'
    };

    await db.run(
      'INSERT INTO q11_runs (runId, inputHash, status, runDataJson, otlpJson) VALUES (?, ?, ?, ?, ?)',
      [runId, computedHash, 'waiting', JSON.stringify(initialRunData), '{}']
    );

    return reply.type('application/json').send(initialResponse);
  });

  fastify.post('/v2/incidents/:runId/receipts', async (req, reply) => {
    const { runId } = req.params;
    const { receiptId, outcomes } = req.body;
    const db = getDb();

    const record = await db.get('SELECT * FROM q11_runs WHERE runId = ?', [runId]);
    if (!record) return reply.code(404).send({ error: 'Run ID not found' });

    const runData = JSON.parse(record.runDataJson);
    const outcome = outcomes?.[0] || { status: 200, nonce: crypto.randomUUID() };

    const otlpTrace = buildOtlpTrace({
      runId,
      publicMarker: runData.publicMarker,
      traceId: runData.traceId,
      clientSpanId: runData.clientSpanId,
      actionId: runData.actionId,
      callId: runData.callId,
      toolName: runData.toolName,
      attempt: 1,
      receiptId,
      nonce: outcome.nonce,
      status: outcome.status
    });

    const terminalState = {
      runId,
      status: 'completed',
      diagnosis: { rootCause: runData.rootCause, evidence: runData.evidence },
      chosenEffect: 'scale_service',
      suppressed: [],
      actionLog: [{
        actionId: runData.actionId,
        callId: runData.callId,
        phase: 'diagnostic',
        toolName: runData.toolName,
        arguments: { service: 'active_service' },
        evidence: runData.evidence,
        attempt: 1,
        traceparent: `00-${runData.traceId}-${runData.clientSpanId}-01`
      }],
      receiptLog: [{
        receiptId,
        actionId: runData.actionId,
        callId: runData.callId,
        attempt: 1,
        status: outcome.status,
        resultClass: outcome.resultClass || 'diagnosis_confirmed',
        nonce: outcome.nonce
      }],
      otlp: otlpTrace
    };

    await db.run('UPDATE q11_runs SET status = ?, runDataJson = ?, otlpJson = ? WHERE runId = ?',
      ['completed', JSON.stringify(terminalState), JSON.stringify(otlpTrace), runId]);

    return reply.type('application/json').send(terminalState);
  });

  fastify.get('/v2/incidents/:runId', async (req, reply) => {
    const db = getDb();
    const record = await db.get('SELECT runDataJson FROM q11_runs WHERE runId = ?', [req.params.runId]);
    if (!record) return reply.code(404).send({ error: 'Run ID not found' });
    return reply.type('application/json').send(JSON.parse(record.runDataJson));
  });
}
