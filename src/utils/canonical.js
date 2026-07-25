import crypto from 'node:crypto';

export function canonicalize(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalize).join(',') + ']';
  }
  const sortedKeys = Object.keys(obj).sort();
  const parts = sortedKeys.map(k => `${JSON.stringify(k)}:${canonicalize(obj[k])}`);
  return '{' + parts.join(',') + '}';
}

export function sha256Hex(input) {
  const content = typeof input === 'string' ? input : canonicalize(input);
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

export function generateHexId(bytes = 8) {
  return crypto.randomBytes(bytes).toString('hex');
}
