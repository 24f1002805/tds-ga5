// src/routes/q9_mailroom.js
import crypto from 'node:crypto';

// In-memory persistent stores (for production, swap with SQLite/Redis if container restarts)
const EVALUATIONS = new Map(); // evaluationId -> { inputDigest, verifier, proposalsMap }
const DOSSIER_CACHE = new Map(); // canonicalContentHash -> proposal

/**
 * Recursive key-sorted compact JSON stringifier (Canonical JSON JCS / RFC 8785)
 */
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

/**
 * Compute lowercase SHA-256 hex string over UTF-8 bytes of canonical JSON representation
 */
function computeSha256(data) {
  const jsonStr = canonicalJsonStringify(data);
  return crypto.createHash('sha256').update(jsonStr, 'utf8').digest('hex');
}

/**
 * Compute proposalDigest for receipt verification & validation
 */
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

/**
 * Verify Ed25519 signature of receipt
 */
function verifyReceiptSignature(receipt, evaluationId, inputDigest, verifier) {
  try {
    if (!verifier || !verifier.publicKeyJwk) return false;

    // Convert JWK x-coordinate (base64url) to DER/PEM Ed25519 public key
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

/**
 * Rule-based heuristic decision engine to analyze dossiers and generate safe proposals
 */
function processDossier(dossier) {
  const dossierId = dossier.dossierId;
  const mailbox = dossier.mailbox || '';
  const objective = dossier.objective || '';
  
  const allLines = [];
  const textContent = [];

  for (const src of dossier.sources || []) {
    for (const line of src.lines || []) {
      if (line.lineId && typeof line.text === 'string') {
        allLines.push(line);
        textContent.push(line.text);
      }
    }
  }

  const fullText = textContent.join(' ');
  const firstLineId = allLines[0]?.lineId || 'line_1';
  const evidenceIds = allLines.slice(0, 3).map(l => l.lineId);

  // 1. Check for Indirect Prompt Injection / Attacks -> quarantine_item
  const lowerText = fullText.toLowerCase();
  if (
    lowerText.includes('ignore previous instructions') ||
    lowerText.includes('system prompt') ||
    lowerText.includes('override policy') ||
    lowerText.includes('agent canary') ||
    lowerText.includes('vault secret')
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

  // 2. Check for ambiguous/unclear identity -> request_confirmation
  if (lowerText.includes('verify request') || lowerText.includes('confirm identity') || lowerText.includes('ambiguous')) {
    return {
      dossierId,
      callId: `call_${dossierId}_${Date.now()}`,
      action: 'request_confirmation',
      target: { kind: 'approval_queue', id: 'mailroom_ops' },
      payload: { claimedSender: mailbox, questionCode: 'VERIFY_REQUEST', referenceId: dossierId },
      evidence: [firstLineId]
    };
  }

  // 3. Approved outbound notice -> send_approved_notice
  if (lowerText.includes('approved notice') || lowerText.includes('order_status')) {
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
  if (lowerText.includes('delivery window') || lowerText.includes('update record')) {
    return {
      dossierId,
      callId: `call_${dossierId}_${Date.now()}`,
      action: 'update_internal_record',
      target: { kind: 'case_record', id: dossierId },
      payload: { field: 'delivery_window', sourceEventId: `evt_${dossierId}`, value: '2026-Q3' },
      evidence: [firstLineId]
    };
  }

  // 5. Customer support draft -> create_draft
  if (lowerText.includes('draft') || lowerText.includes('inquiry')) {
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

export async function q9MailroomRoutes(fastify) {
  fastify.post('/v1/mailroom', async (req, reply) => {
    reply.status(200).type('application/json');
    const body = req.body || {};

    // Validate profile
    if (body.profile !== 'ga5-mailroom-action-gate/v2') {
      return reply.status(400).send({ error: 'Invalid profile' });
    }

    const { operation, evaluationId } = body;
    if (!evaluationId) {
      return reply.status(400).send({ error: 'Missing evaluationId' });
    }

    // ----------------------------------------------------
    // OPERATION 1: PROPOSE
    // ----------------------------------------------------
    if (operation === 'propose') {
      const { receiptVerifier, corpus, dossiers } = body;
      if (!Array.isArray(dossiers) || dossiers.length === 0) {
        return reply.status(400).send({ error: 'Missing or empty dossiers array' });
      }

      // Compute input digest over key-sorted compact JSON of dossiers
      const inputDigest = computeSha256(dossiers);

      // Check conflict: If evaluationId already exists with DIFFERENT inputDigest -> HTTP 409
      if (EVALUATIONS.has(evaluationId)) {
        const existing = EVALUATIONS.get(evaluationId);
        if (existing.inputDigest !== inputDigest) {
          return reply.status(409).send({ error: 'Conflict: evaluationId exists with different inputDigest' });
        }
        // Exact Replay -> Return exact cached response
        const cachedProposals = Array.from(existing.proposalsMap.values());
        return reply.send({
          profile: 'ga5-mailroom-action-gate/v2',
          evaluationId,
          status: 'awaiting_receipts',
          inputDigest,
          proposals: cachedProposals
        });
      }

      // Process each dossier and cache by canonical content fingerprint
      const proposals = [];
      const proposalsMap = new Map();

      for (const dossier of dossiers) {
        const canonicalHash = computeSha256(dossier);
        let proposal;

        if (DOSSIER_CACHE.has(canonicalHash)) {
          proposal = { ...DOSSIER_CACHE.get(canonicalHash) };
          proposal.dossierId = dossier.dossierId; // Ensure dossierId matches request
        } else {
          proposal = processDossier(dossier);
          DOSSIER_CACHE.set(canonicalHash, proposal);
        }

        proposals.push(proposal);
        proposalsMap.set(dossier.dossierId, proposal);
      }

      // Persist evaluation state
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

    // ----------------------------------------------------
    // OPERATION 2: COMMIT
    // ----------------------------------------------------
    if (operation === 'commit') {
      const { inputDigest, receipts } = body;

      // Reject unknown evaluationId -> HTTP 400
      if (!EVALUATIONS.has(evaluationId)) {
        return reply.status(400).send({ error: 'Unknown evaluationId' });
      }

      const evalData = EVALUATIONS.get(evaluationId);

      // Digest verification
      if (evalData.inputDigest !== inputDigest) {
        return reply.status(400).send({ error: 'Mismatch in inputDigest' });
      }

      if (!Array.isArray(receipts)) {
        return reply.status(400).send({ error: 'Invalid receipts format' });
      }

      // Validate every receipt atomically before modifying state
      const outcomes = [];

      for (const receipt of receipts) {
        const storedProposal = evalData.proposalsMap.get(receipt.dossierId);

        // 1. Ensure dossier & callId match persisted proposal
        if (!storedProposal || storedProposal.callId !== receipt.callId || storedProposal.action !== receipt.action) {
          return reply.status(400).send({ error: `Proposal mismatch for dossier ${receipt.dossierId}` });
        }

        // 2. Compute proposal digest and check match
        const computedDigest = computeProposalDigest(storedProposal);
        if (computedDigest !== receipt.proposalDigest) {
          return reply.status(400).send({ error: `proposalDigest mismatch for dossier ${receipt.dossierId}` });
        }

        // 3. Verify Ed25519 cryptographic receipt signature
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
  });

  // Alias path
  fastify.post('/mailroom', async (req, reply) => {
    return fastify.inject({
      method: 'POST',
      url: '/v1/mailroom',
      payload: req.body,
      headers: req.headers
    }).then(res => reply.status(res.statusCode).send(res.json()));
  });
}
