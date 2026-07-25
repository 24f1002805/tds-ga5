import Fastify from 'fastify';
import { initDb } from './db.js';
import { q2ProrationRoutes } from './routes/q2_proration.js';
import { q3GuardrailRoutes } from './routes/q3_guardrail.js';
import { q4ScannerRoutes } from './routes/q4_scanner.js';
import { q5LoopGuardRoutes } from './routes/q5_loopguard.js';
import { q6McpRoutes } from './routes/q6_mcp.js';
import { q8GuardrailRoutes } from './routes/q8_guardrail.js';
import { q9MailroomRoutes } from './routes/q9_mailroom.js';
import { q10A2aRoutes } from './routes/q10_a2a.js';
import { q11IncidentsRoutes } from './routes/q11_incidents.js';

const fastify = Fastify({
  logger: true,
  bodyLimit: 786432
});

fastify.get('/', async () => ({ status: 'ok', service: 'GA5 Master Agent Suite' }));

async function start() {
  try {
    await initDb();
    
    // Register All Question Handlers
    await fastify.register(q2ProrationRoutes);
    await fastify.register(q3GuardrailRoutes);
    await fastify.register(q4ScannerRoutes);
    await fastify.register(q5LoopGuardRoutes);
    await fastify.register(q6McpRoutes);
    await fastify.register(q8GuardrailRoutes);
    await fastify.register(q9MailroomRoutes);
    await fastify.register(q10A2aRoutes);
    await fastify.register(q11IncidentsRoutes);

    const port = process.env.PORT || 3000;
    await fastify.listen({ port: Number(port), host: '0.0.0.0' });
    console.log(`Master GA5 Agent Suite running on port ${port}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

start();
