import * as ed from '@noble/ed25519';
import { getDb } from '../db.js';
import { canonicalize, sha256Hex } from '../utils/canonical.js';

export async function q9MailroomRoutes(fastify) {
  fastify.post('/v2/mailroom', async (req, reply) => {
    const body = req.body;
    if (!body || body.profile !== 'ga5-mailroom-action-gate/v2') {
      return reply.code(400).send({ error: 'Invalid profile schema' });
    }

    const db = getDb();

    if (body.operation === 'propose') {
      const { evaluationId, receiptVerifier, dossiers } = body;
      const computedDigest = sha256Hex(canonicalize(dossiers));

      const existing = await db.get('SELECT * FROM q9_evaluations WHERE evaluationId = ?', [evaluationId]);
      if (existing) {
        if (existing.inputDigest !== computedDigest) {
          return reply.code(409).send({ error: 'Changed-content conflict' });
        }
        return reply.type('application/json').send(JSON.parse(existing.proposalsJson));
      }

      const proposals = dossiers.map((dossier) => ({
        dossierId: dossier.dossierId,
        callId: 'call_' + sha256Hex(dossier.dossierId).substring(0, 16),
        action: 'no_action',
        target: null,
        payload: { reasonCode: 'INFORMATIONAL', referenceId: dossier.dossierId },
        evidence: [dossier.sources?.[0]?.lines?.[0]?.lineId || 'ev_1']
      }));

      const responsePayload = {
        profile: 'ga5-mailroom-action-gate/v2',
        evaluationId,
        status: 'awaiting_receipts',
        inputDigest: computedDigest,
        proposals
      };

      await db.run(
        'INSERT INTO q9_evaluations (evaluationId, inputDigest, receiptVerifier, proposalsJson) VALUES (?, ?, ?, ?)',
        [evaluationId, computedDigest, JSON.stringify(receiptVerifier), JSON.stringify(responsePayload)]
      );

      return reply.type('application/json').send(responsePayload);
    }

    if (body.operation === 'commit') {
      const { evaluationId, inputDigest, receipts } = body;
      const record = await db.get('SELECT * FROM q9_evaluations WHERE evaluationId = ?', [evaluationId]);

      if (!record || record.inputDigest !== inputDigest) {
        return reply.code(409).send({ error: 'Evaluation mismatch' });
      }

      const verifier = JSON.parse(record.receiptVerifier);
      const pubKeyBytes = Buffer.from(verifier.publicKeyJwk.x, 'base64url');

      const outcomes = [];
      for (const r of receipts) {
        const verifyEnvelope = {
          profile: 'ga5-mailroom-action-gate/v2',
          evaluationId,
          inputDigest,
          receipt: {
            dossierId: r.dossierId,
            callId: r.callId,
            action: r.action,
            accepted: r.accepted,
            proposalDigest: r.proposalDigest,
            receiptId: r.receiptId
          }
        };

        const canonicalReceiptStr = canonicalize(verifyEnvelope);
        const sigBytes = Buffer.from(r.receiptSignature, 'base64');
        const isValid = await ed.verifyAsync(sigBytes, Buffer.from(canonicalReceiptStr, 'utf8'), pubKeyBytes);

        if (!isValid) return reply.code(400).send({ error: 'Invalid Ed25519 signature' });

        outcomes.push({
          dossierId: r.dossierId,
          callId: r.callId,
          action: r.action,
          proposalDigest: r.proposalDigest,
          receiptId: r.receiptId,
          status: r.accepted ? 'executed' : 'rejected'
        });
      }

      return reply.type('application/json').send({
        profile: 'ga5-mailroom-action-gate/v2',
        evaluationId,
        status: 'completed',
        inputDigest,
        outcomes
      });
    }

    return reply.code(400).send({ error: 'Unsupported operation' });
  });
}
