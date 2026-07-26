
// src/routes/q6_mcp.js
import crypto from 'node:crypto';

export async function q6McpRoutes(fastify) {
  const REGISTERED_EMAIL = '24f1002805@ds.study.iitm.ac.in';

  const handleMcpRequest = async (req, reply) => {
    const body = req.body || {};
    const { jsonrpc, id, method, params } = body;

    // Handle JSON-RPC request validation
    if (jsonrpc !== '2.0') {
      return reply.type('application/json').send({
        jsonrpc: '2.0',
        id: id || null,
        error: { code: -32600, message: 'Invalid Request' }
      });
    }

    // 1. MCP Initialize
    if (method === 'initialize') {
      return reply.type('application/json').send({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: {
            tools: {}
          },
          serverInfo: {
            name: 'tds-ga5-mcp-server',
            version: '1.0.0'
          }
        }
      });
    }

    // 2. MCP Initialized Notification
    if (method === 'notifications/initialized') {
      return reply.code(200).send();
    }

    // 3. MCP Tools List
    if (method === 'tools/list') {
      return reply.type('application/json').send({
        jsonrpc: '2.0',
        id,
        result: {
          tools: [
            {
              name: 'solve_challenge',
              description: 'Solves the exam header challenge and returns a 16-character hex hash',
              inputSchema: {
                type: 'object',
                properties: {},
                required: []
              }
            }
          ]
        }
      });
    }

    // 4. MCP Tools Call
    if (method === 'tools/call') {
      const toolName = params?.name;

      if (toolName !== 'solve_challenge') {
        return reply.type('application/json').send({
          jsonrpc: '2.0',
          id,
          error: { code: -32601, message: `Tool not found: ${toolName}` }
        });
      }

      // Read fresh per-call challenge header (Fastify lowercases header names automatically)
      const challenge = String(req.headers['x-exam-challenge'] || '').toLowerCase();
      const normalizedEmail = REGISTERED_EMAIL.trim().toLowerCase();

      // SHA-256("${challenge}:${normalizedEmail}")
      const rawText = `${challenge}:${normalizedEmail}`;
      const hash = crypto.createHash('sha256').update(rawText).digest('hex');
      const responseText = hash.substring(0, 16);

      return reply.type('application/json').send({
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            {
              type: 'text',
              text: responseText
            }
          ]
        }
      });
    }

    return reply.type('application/json').send({
      jsonrpc: '2.0',
      id,
      error: { code: -32601, message: 'Method not found' }
    });
  };

  // Register endpoints across possible probe request paths
  fastify.post('/mcp', handleMcpRequest);
  fastify.post('/v1/mcp', handleMcpRequest);
}
