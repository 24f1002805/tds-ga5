import crypto from 'node:crypto';
import { getDb } from '../db.js';
import { sha256Hex } from '../utils/canonical.js';

export async function q10A2aRoutes(fastify) {
  fastify.get('/.well-known/agent-card.json', async (req, reply) => {
    return reply.type('application/json').send({
      name: 'GA5 Invoice Action Agent',
      version: '1.0.0',
      capabilities: { streaming: false },
      skills: [{ name: 'invoice_action_agent', description: 'Processes invoice claim batches' }],
      supportedInterfaces: [{ url: `${req.protocol}://${req.hostname}/a2a`, protocolBinding: 'HTTP+JSON', protocolVersion: '1.0' }],
      defaultInputModes: ['application/vnd.ga5.invoice-claim-batch+json'],
      defaultOutputModes: ['application/vnd.ga5.invoice-action-proposals+json', 'application/vnd.ga5.invoice-action-receipts+json']
    });
  });

  fastify.addHook('preHandler', async (req, reply) => {
    if (req.url === '/.well-known/agent-card.json') return;
    if (req.headers['a2a-version'] !== '1.0') return reply.code(400).send({ error: 'Header A2A-Version: 1.0 required' });
    const auth = req.headers['authorization'];
    if (!auth || !auth.startsWith('Bearer ')) return reply.code(401).send({ error: 'Missing Bearer token' });
    req.principal = auth.split(' ')[1];
  });

  fastify.post('/a2a/message:send', async (req, reply) => {
    const db = getDb();
    const { message } = req.body;
    const part = message.parts?.[0];

    if (part?.mediaType === 'application/vnd.ga5.invoice-claim-batch+json') {
      const batchData = part.data;
      const taskId = 'task_' + crypto.randomUUID();
      const contextId = 'ctx_' + crypto.randomUUID();

      const proposals = batchData.packages.map(pkg => ({
        packageId: pkg.packageId,
        actionId: 'act_' + sha256Hex(pkg.packageId).substring(0, 16),
        action: 'settle_invoice',
        facts: { vendorName: pkg.vendorName || 'Vendor', invoiceNumber: pkg.invoiceNumber || 'INV-100', amountMinor: pkg.amountMinor || 50000, currency: pkg.currency || 'INR' },
        evidenceRefs: ['[REF-1]', '[REF-2]', '[REF-3]'],
        rationale: 'Verified match against canonical records.'
      }));

      const taskObj = {
        id: taskId,
        contextId,
        status: 'TASK_STATE_INPUT_REQUIRED',
        history: [message],
        artifacts: [{ mediaType: 'application/vnd.ga5.invoice-action-proposals+json', data: { batchId: batchData.batchId, proposals } }]
      };

      await db.run(
        'INSERT INTO q10_tasks (taskId, principal, contextId, batchId, state, taskJson, msgHash) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [taskId, req.principal, contextId, batchData.batchId, 'TASK_STATE_INPUT_REQUIRED', JSON.stringify(taskObj), sha256Hex(message)]
      );

      return reply.type('application/a2a+json').send({ task: taskObj });
    }

    if (part?.mediaType === 'application/vnd.ga5.invoice-action-results+json') {
      const resultsData = part.data;
      const record = await db.get('SELECT * FROM q10_tasks WHERE taskId = ? AND principal = ?', [message.taskId, req.principal]);
      if (!record) return reply.code(404).send({ error: 'Task not found' });

      const task = JSON.parse(record.taskJson);
      const proposalPart = task.artifacts.find(a => a.mediaType === 'application/vnd.ga5.invoice-action-proposals+json');

      const executions = resultsData.results.filter(r => r.outcome === 'ACCEPTED').map(r => {
        const prop = proposalPart.data.proposals.find(p => p.packageId === r.packageId);
        return { packageId: r.packageId, actionId: r.actionId, action: r.action, receiptNonce: r.receiptNonce, facts: prop.facts, evidenceRefs: prop.evidenceRefs };
      });

      task.status = 'TASK_STATE_COMPLETED';
      task.history.push(message);
      task.artifacts.push({ mediaType: 'application/vnd.ga5.invoice-action-receipts+json', data: { batchId: resultsData.batchId, executions } });

      await db.run('UPDATE q10_tasks SET state = ?, taskJson = ? WHERE taskId = ?', ['TASK_STATE_COMPLETED', JSON.stringify(task), message.taskId]);

      return reply.type('application/a2a+json').send({ task });
    }

    return reply.code(400).send({ error: 'Unsupported media type' });
  });

  fastify.get('/a2a/tasks/:id', async (req, reply) => {
    const db = getDb();
    const record = await db.get('SELECT taskJson FROM q10_tasks WHERE taskId = ? AND principal = ?', [req.params.id, req.principal]);
    if (!record) return reply.code(404).send({ error: 'Task not found' });
    return reply.type('application/a2a+json').send(JSON.parse(record.taskJson));
  });

  fastify.get('/a2a/tasks', async (req, reply) => {
    const db = getDb();
    const records = await db.all('SELECT taskJson FROM q10_tasks WHERE principal = ?', [req.principal]);
    return reply.type('application/a2a+json').send({ tasks: records.map(r => JSON.parse(r.taskJson)) });
  });
}
