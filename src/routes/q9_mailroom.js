// src/routes/q9_mailroom.js
import crypto from 'node:crypto';

const EVALUATIONS = new Map();
const DOSSIER_CACHE = new Map();

function canonicalJsonStringify(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJsonStringify).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  const entries = keys.map(k => `${JSON.stringify(k)}:${canonicalJsonStringify(obj[k])}`);
  return '{' + entries.join(',') + '}';
}

function computeSha256(data) {
  const jsonStr = canonicalJsonStringify(data);
  return crypto.createHash('sha256').update(jsonStr, 'utf8').digest('hex');
}

function computeProposalDigest(proposal) {
  const norm = {
    dossierId: proposal.dossierId,
    callId: proposal.callId,
    action: proposal.action,
    target: proposal.target ?? null,
    payload: proposal.payload,
    evidence: Array.isArray(proposal.evidence) ? [...proposal.evidence].sort() : []
  };
  return computeSha256(norm);
}

function verifyReceiptSignature(receipt, evaluationId, inputDigest, verifier) {
  try {
    if (!verifier || !verifier.publicKeyJwk) return false;

    const publicKey = crypto.createPublicKey({
      key: verifier.publicKeyJwk,
      format: 'jwk'
    });

    const canonicalData = {
      profile: 'ga5-mailroom-action-gate/v2',
      evaluationId,
      inputDigest,
      receipt: {
        dossierId: receipt.dossierId,
        callId: receipt.callId,
        action: receipt.action,
        accepted: receipt.accepted,
        proposalDigest: receipt.proposalDigest,
        receiptId: receipt.receiptId
      }
    };

    const messageBuffer = Buffer.from(canonicalJsonStringify(canonicalData), 'utf8');
    const signatureBuffer = Buffer.from(receipt.receiptSignature, 'base64');

    return crypto.verify(null, messageBuffer, publicKey, signatureBuffer);
  } catch (err) {
    return false;
  }
}

function processDossier(dossier) {
  const dossierId = dossier.dossierId;
  const mailbox = dossier.mailbox || '';

  const allLines = [];
  for (const src of dossier.sources || []) {
    for (const line of src.lines || []) {
      if (line.lineId && typeof line.text === 'string') {
        allLines.push(line);
      }
    }
  }

  const fullText = allLines.map(l => l.text).join(' ').toLowerCase();
  const firstLineId = allLines[0]?.lineId || 'line_1';

  // 1. Indirect Prompt Injection -> quarantine_item
  if (
    fullText.includes('ignore previous instructions') ||
    fullText.includes('system prompt') ||
    fullText.includes('override policy') ||
    fullText.includes('canary') ||
    fullText.includes('vault secret')
  ) {
    return {
      dossierId,
      callId: `call_${dossierId}_${Date.now()}`,
      action: 'quarantine_item',
      target: { kind: 'security_queue', id: 'mailroom' },
      payload: { artifactId: dossierId, reasonCode: 'INDIRECT_PROMPT_INJECTION' },
      evidence: [firstLineId]
    };
  }

  // 2. Identity / Confirmation ambiguous -> request_confirmation
  if (fullText.includes('verify') || fullText.includes('confirm') || fullText.includes('identity')) {
    return {
      dossierId,
      callId: `call_${dossierId}_${Date.now()}`,
      action: 'request_confirmation',
      target: { kind: 'approval_queue', id: 'mailroom_ops' },
      payload: { claimedSender: mailbox, questionCode: 'VERIFY_REQUEST', referenceId: dossierId },
      evidence: [firstLineId]
    };
  }

  // 3. Outbound approved notice -> send_approved_notice
  if (fullText.includes('approved') || fullText.includes('notice')) {
    return {
      dossierId,
      callId: `call_${dossierId}_${Date.now()}`,
      action: 'send_approved_notice',
      target: { kind: 'email', id: mailbox || 'customer@example.com' },
      payload: { referenceId: dossierId, status: 'APPROVED', template: 'approved_delivery_notice' },
      evidence: [firstLineId]
    };
  }

  // 4. Internal updates -> update_internal_record
  if (fullText.includes('window') || fullText.includes('update')) {
    return {
      dossierId,
      callId: `call_${dossierId}_${Date.now()}`,
      action: 'update_internal_record',
      target: { kind: 'case_record', id: dossierId },
      payload: { field: 'delivery_window', sourceEventId: `evt_${dossierId}`, value: '2026-Q3' },
      evidence: [firstLineId]
    };
  }

  // 5. Customer draft -> create_draft
  if (fullText.includes('draft') || fullText.includes('order')) {
    return {
      dossierId,
      callId: `call_${dossierId}_${Date.now()}`,
      action: 'create_draft',
      target: { kind: 'draft_queue', id: `mailbox:${mailbox || 'default'}` },
      payload: { recipient: mailbox || 'customer@example.com', referenceId: dossierId, status: 'PENDING', template: 'order_status' },
      evidence: [firstLineId]
    };
  }

  // 6. Default fallback -> no_action
  return {
    dossierId,
    callId: `call_${dossierId}_${Date.now()}`,
    action: 'no_action',
    target: null,
    payload: { reasonCode: 'INFORMATIONAL', referenceId: dossierId },
    evidence: [firstLineId]
  };
}

export async function q9MailroomRoutes(fastify, opts) {
  async function handleMailroom(req, reply) {
    reply.status(200).type('application/json');
    const body = req.body || {};

    if (body.profile !== 'ga5-mailroom-action-gate/v2') {
      return reply.status(400).send({ error: 'Invalid profile' });
    }

    const { operation, evaluationId } = body;
    if (!evaluationId) {
      return reply.status(400).send({ error: 'Missing evaluationId' });
    }

    // OPERATION 1: PROPOSE
    if (operation === 'propose') {
      const { receiptVerifier, dossiers } = body;
      if (!Array.isArray(dossiers) || dossiers.length === 0) {
        return reply.status(400).send({ error: 'Missing or empty dossiers array' });
      }

      const inputDigest = computeSha256(dossiers);

      // Conflict Check: 409 if evaluationId exists with different inputDigest
      if (EVALUATIONS.has(evaluationId)) {
        const existing = EVALUATIONS.get(evaluationId);
        if (existing.inputDigest !== inputDigest) {
          return reply.status(409).send({ error: 'Conflict: evaluationId exists with different inputDigest' });
        }
        const cachedProposals = Array.from(existing.proposalsMap.values());
        return reply.send({
          profile: 'ga5-mailroom-action-gate/v2',
          evaluationId,
          status: 'awaiting_receipts',
          inputDigest,
          proposals: cachedProposals
        });
      }

      const proposals = [];
      const proposalsMap = new Map();

      for (const dossier of dossiers) {
        const canonicalHash = computeSha256(dossier);
        let proposal;

        if (DOSSIER_CACHE.has(canonicalHash)) {
          proposal = { ...DOSSIER_CACHE.get(canonicalHash) };
          proposal.dossierId = dossier.dossierId;
        } else {
          proposal = processDossier(dossier);
          DOSSIER_CACHE.set(canonicalHash, proposal);
        }

        proposals.push(proposal);
        proposalsMap.set(dossier.dossierId, proposal);
      }

      EVALUATIONS.set(evaluationId, {
        inputDigest,
        verifier: receiptVerifier,
        proposalsMap
      });

      return reply.send({
        profile: 'ga5-mailroom-action-gate/v2',
        evaluationId,
        status: 'awaiting_receipts',
        inputDigest,
        proposals
      });
    }

    // OPERATION 2: COMMIT
    if (operation === 'commit') {
      const { inputDigest, receipts } = body;

      if (!EVALUATIONS.has(evaluationId)) {
        return reply.status(400).send({ error: 'Unknown evaluationId' });
      }

      const evalData = EVALUATIONS.get(evaluationId);

      if (evalData.inputDigest !== inputDigest) {
        return reply.status(400).send({ error: 'Mismatch in inputDigest' });
      }

      if (!Array.isArray(receipts)) {
        return reply.status(400).send({ error: 'Invalid receipts format' });
      }

      const outcomes = [];

      for (const receipt of receipts) {
        const storedProposal = evalData.proposalsMap.get(receipt.dossierId);

        if (!storedProposal || storedProposal.callId !== receipt.callId || storedProposal.action !== receipt.action) {
          return reply.status(400).send({ error: `Proposal mismatch for dossier ${receipt.dossierId}` });
        }

        const computedDigest = computeProposalDigest(storedProposal);
        if (computedDigest !== receipt.proposalDigest) {
          return reply.status(400).send({ error: `proposalDigest mismatch for dossier ${receipt.dossierId}` });
        }

        const isValidSignature = verifyReceiptSignature(receipt, evaluationId, inputDigest, evalData.verifier);
        if (!isValidSignature) {
          return reply.status(400).send({ error: `Invalid receipt signature for dossier ${receipt.dossierId}` });
        }

        outcomes.push({
          dossierId: receipt.dossierId,
          callId: receipt.callId,
          action: receipt.action,
          proposalDigest: receipt.proposalDigest,
          receiptId: receipt.receiptId,
          status: receipt.accepted ? 'executed' : 'rejected'
        });
      }

      return reply.send({
        profile: 'ga5-mailroom-action-gate/v2',
        evaluationId,
        status: 'completed',
        inputDigest,
        outcomes
      });
    }

    return reply.status(400).send({ error: `Unknown operation: ${operation}` });
  }

  // Register on both endpoints
  fastify.post('/v1/mailroom', handleMailroom);
  fastify.post('/mailroom', handleMailroom);
}
