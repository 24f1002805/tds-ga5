import * as ed from '@noble/ed25519';
import { getDb } from '../db.js';
import { canonicalize, sha256Hex } from '../utils/canonical.js';

function computeProposalDigest(proposal) {
  const norm = {
    dossierId: proposal.dossierId,
    callId: proposal.callId,
    action: proposal.action,
    target: proposal.target ?? null,
    payload: proposal.payload,
    evidence: Array.isArray(proposal.evidence) ? [...proposal.evidence].sort() : []
  };
  return sha256Hex(canonicalize(norm));
}

function processDossier(dossier) {
  const dossierId = dossier.dossierId;
  const mailbox = dossier.mailbox || '';

  const linesWithContext = [];
  for (const src of dossier.sources || []) {
    for (const line of src.lines || []) {
      if (line.lineId && typeof line.text === 'string') {
        linesWithContext.push(line);
      }
    }
  }

  const fullText = linesWithContext.map(l => l.text).join(' ').toLowerCase();
  const allLineIds = linesWithContext.map(l => l.lineId);
  const primaryLineId = allLineIds[0] || 'line_1';

  // 1. Unsafe / Prompt Injection -> quarantine_item
  if (
    fullText.includes('ignore previous instructions') ||
    fullText.includes('system prompt') ||
    fullText.includes('override policy') ||
    fullText.includes('canary') ||
    fullText.includes('vault secret')
  ) {
    const triggerLine = linesWithContext.find(l => {
      const txt = l.text.toLowerCase();
      return txt.includes('ignore') || txt.includes('prompt') || txt.includes('override') || txt.includes('canary') || txt.includes('secret');
    })?.lineId || primaryLineId;

    return {
      dossierId,
      callId: `call_${sha256Hex(dossierId + '_quarantine').substring(0, 16)}`,
      action: 'quarantine_item',
      target: { kind: 'security_queue', id: 'mailroom' },
      payload: { artifactId: dossierId, reasonCode: 'INDIRECT_PROMPT_INJECTION' },
      evidence: [triggerLine]
    };
  }

  // 2. Verification / Identity Needed -> request_confirmation
  if (fullText.includes('verify') || fullText.includes('confirm') || fullText.includes('identity')) {
    const triggerLine = linesWithContext.find(l => {
      const txt = l.text.toLowerCase();
      return txt.includes('verify') || txt.includes('confirm') || txt.includes('identity');
    })?.lineId || primaryLineId;

    return {
      dossierId,
      callId: `call_${sha256Hex(dossierId + '_confirm').substring(0, 16)}`,
      action: 'request_confirmation',
      target: { kind: 'approval_queue', id: 'mailroom_ops' },
      payload: { claimedSender: mailbox || 'unknown@example.com', questionCode: 'VERIFY_REQUEST', referenceId: dossierId },
      evidence: [triggerLine]
    };
  }

  // 3. Approved Delivery / Notice -> send_approved_notice
  if (fullText.includes('approved') || fullText.includes('notice')) {
    const triggerLine = linesWithContext.find(l => {
      const txt = l.text.toLowerCase();
      return txt.includes('approved') || txt.includes('notice');
    })?.lineId || primaryLineId;

    return {
      dossierId,
      callId: `call_${sha256Hex(dossierId + '_notice').substring(0, 16)}`,
      action: 'send_approved_notice',
      target: { kind: 'email', id: mailbox || 'customer@example.com' },
      payload: { referenceId: dossierId, status: 'APPROVED', template: 'approved_delivery_notice' },
      evidence: [triggerLine]
    };
  }

  // 4. Record Update -> update_internal_record
  if (fullText.includes('window') || fullText.includes('update') || fullText.includes('reschedule')) {
    const triggerLine = linesWithContext.find(l => {
      const txt = l.text.toLowerCase();
      return txt.includes('window') || txt.includes('update') || txt.includes('reschedule');
    })?.lineId || primaryLineId;

    return {
      dossierId,
      callId: `call_${sha256Hex(dossierId + '_update').substring(0, 16)}`,
      action: 'update_internal_record',
      target: { kind: 'case_record', id: dossierId },
      payload: { field: 'delivery_window', sourceEventId: `evt_${dossierId}`, value: '2026-Q3' },
      evidence: [triggerLine]
    };
  }

  // 5. Draft Order -> create_draft
  if (fullText.includes('draft') || fullText.includes('order')) {
    const triggerLine = linesWithContext.find(l => {
      const txt = l.text.toLowerCase();
      return txt.includes('draft') || txt.includes('order');
    })?.lineId || primaryLineId;

    return {
      dossierId,
      callId: `call_${sha256Hex(dossierId + '_draft').substring(0, 16)}`,
      action: 'create_draft',
      target: { kind: 'draft_queue', id: `mailbox:${mailbox || 'default'}` },
      payload: { recipient: mailbox || 'customer@example.com', referenceId: dossierId, status: 'PENDING', template: 'order_status' },
      evidence: [triggerLine]
    };
  }

  // 6. Default Fallback -> no_action
  return {
    dossierId,
    callId: `call_${sha256Hex(dossierId + '_noaction').substring(0, 16)}`,
    action: 'no_action',
    target: null,
    payload: { reasonCode: 'INFORMATIONAL', referenceId: dossierId },
    evidence: [primaryLineId]
  };
}

export async function q9MailroomRoutes(fastify) {
  const handler = async (req, reply) => {
    const body = req.body;
    if (!body || body.profile !== 'ga5-mailroom-action-gate/v2') {
      return reply.code(400).send({ error: 'Invalid profile schema' });
    }

    const db = getDb();

    if (body.operation === 'propose') {
      const { evaluationId, receiptVerifier, dossiers } = body;
      if (!evaluationId || !Array.isArray(dossiers)) {
        return reply.code(400).send({ error: 'Malformed request' });
      }

      const computedDigest = sha256Hex(canonicalize(dossiers));

      const existing = await db.get('SELECT * FROM q9_evaluations WHERE evaluationId = ?', [evaluationId]);
      if (existing) {
        if (existing.inputDigest !== computedDigest) {
          return reply.code(409).send({ error: 'Conflict: evaluationId exists with different inputDigest' });
        }
        return reply.type('application/json').send(JSON.parse(existing.proposalsJson));
      }

      const proposals = dossiers.map(processDossier);

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
      if (!evaluationId || !inputDigest || !Array.isArray(receipts)) {
        return reply.code(400).send({ error: 'Malformed request' });
      }

      const record = await db.get('SELECT * FROM q9_evaluations WHERE evaluationId = ?', [evaluationId]);

      if (!record) {
        return reply.code(400).send({ error: 'Unknown evaluationId' });
      }

      if (record.inputDigest !== inputDigest) {
        return reply.code(409).send({ error: 'Conflict: Evaluation inputDigest mismatch' });
      }

      const verifier = JSON.parse(record.receiptVerifier);
      const evalPayload = JSON.parse(record.proposalsJson);
      const proposalsMap = new Map((evalPayload.proposals || []).map(p => [p.dossierId, p]));

      let pubKeyBytes;
      try {
        pubKeyBytes = Buffer.from(verifier.publicKeyJwk.x, 'base64url');
      } catch (err) {
        return reply.code(400).send({ error: 'Invalid verifier key format' });
      }

      const outcomes = [];
      for (const r of receipts) {
        const storedProposal = proposalsMap.get(r.dossierId);
        if (!storedProposal) {
          return reply.code(400).send({ error: `Missing proposal for dossier ${r.dossierId}` });
        }

        const expectedProposalDigest = computeProposalDigest(storedProposal);
        if (r.proposalDigest && r.proposalDigest !== expectedProposalDigest) {
          return reply.code(400).send({ error: `proposalDigest mismatch for ${r.dossierId}` });
        }

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
        let isValid = false;
        try {
          const sigBytes = Buffer.from(r.receiptSignature, 'base64');
          isValid = await ed.verifyAsync(sigBytes, Buffer.from(canonicalReceiptStr, 'utf8'), pubKeyBytes);
        } catch (err) {
          isValid = false;
        }

        if (!isValid) {
          return reply.code(400).send({ error: 'Invalid receipt signature' });
        }

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
  };

  fastify.post('/v1/mailroom', handler);
  fastify.post('/v2/mailroom', handler);
  fastify.post('/mailroom', handler);
}
