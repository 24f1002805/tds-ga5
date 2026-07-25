export function buildOtlpTrace({ runId, publicMarker, traceId, clientSpanId, actionId, callId, toolName, attempt, receiptId, nonce, status = 200 }) {
  const rootSpanId = clientSpanId || '1122334455667788';
  const validTraceId = traceId || '00000000000000000000000000000001';

  return {
    resourceSpans: [{
      scopeSpans: [{
        spans: [
          {
            traceId: validTraceId,
            spanId: rootSpanId,
            parentSpanId: '',
            name: `POST /v2/incidents`,
            kind: 2,
            attributes: [
              { key: 'ga5.run.id', value: { stringValue: runId } },
              { key: 'ga5.public.marker', value: { stringValue: publicMarker } }
            ]
          },
          {
            traceId: validTraceId,
            spanId: '8877665544332211',
            parentSpanId: rootSpanId,
            name: 'chat incident-plan',
            kind: 3,
            attributes: [
              { key: 'ga5.run.id', value: { stringValue: runId } },
              { key: 'ga5.public.marker', value: { stringValue: publicMarker } },
              { key: 'gen_ai.operation.name', value: { stringValue: 'chat' } },
              { key: 'gen_ai.request.model', value: { stringValue: 'heuristic-lite' } }
            ]
          },
          {
            traceId: validTraceId,
            spanId: '9988776655443322',
            parentSpanId: rootSpanId,
            name: `execute_tool ${toolName}`,
            kind: 1,
            attributes: [
              { key: 'ga5.run.id', value: { stringValue: runId } },
              { key: 'ga5.public.marker', value: { stringValue: publicMarker } },
              { key: 'ga5.action.id', value: { stringValue: actionId } },
              { key: 'gen_ai.tool.name', value: { stringValue: toolName } },
              { key: 'gen_ai.tool.call.id', value: { stringValue: callId } },
              { key: 'gen_ai.operation.name', value: { stringValue: 'execute_tool' } }
            ]
          },
          {
            traceId: validTraceId,
            spanId: clientSpanId || 'aabbccddeeff0011',
            parentSpanId: '9988776655443322',
            name: `POST tool/${toolName}`,
            kind: 3,
            attributes: [
              { key: 'ga5.run.id', value: { stringValue: runId } },
              { key: 'ga5.public.marker', value: { stringValue: publicMarker } },
              { key: 'ga5.action.id', value: { stringValue: actionId } },
              { key: 'ga5.attempt', value: { intValue: attempt } },
              { key: 'ga5.receipt.id', value: { stringValue: receiptId || 'rcpt_default' } },
              { key: 'ga5.receipt.nonce', value: { stringValue: nonce || 'nonce_default' } },
              { key: 'http.request.method', value: { stringValue: 'POST' } },
              { key: 'http.request.resend_count', value: { intValue: attempt - 1 } }
            ],
            status: { code: status === 200 ? 1 : 2 }
          }
        ]
      }]
    }]
  };
}
